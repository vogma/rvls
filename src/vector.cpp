/*
 * vector.cpp: RVV checking for RVLS, see vector.hpp.
 */

#include "vector.hpp"
#include "hart.hpp"
#include "context.hpp"
#include "global.hpp"
#include "mmu.h"
#include <format>
#include <cstring>
#include <algorithm>
#include <sstream>

using namespace std;

// Marks a step that executed no instruction (0 is an illegal encoding).
static const reg_t NO_INSN = 0;

static string hexBytes(const u8 *p, size_t n){
    string s;
    for(size_t i = n; i-- > 0;) s += format("{:02x}", p[i]);
    return s;
}

VectorChecker::VectorChecker(Hart &hart) : hart(hart) {
    proc = hart.proc;
    state = hart.state;
    vlen = proc->VU.VLEN;
    vlenb = vlen / 8;
    xlen = proc->get_xlen();
    isa = make_unique<isa_parser_t>(hart.isaStorage.c_str(), hart.privStorage.c_str());
    disasm = make_unique<disassembler_t>(isa.get());
    dutVrf.assign(32 * vlenb, 0);
    preVrf.assign(32 * vlenb, 0);
    evVrf.assign(32 * vlenb, 0);
    evWritten.assign(32 * vlenb, 0);
    // The DUT resets to Spike's reset values.
    dutCsr = readSpikeCsrs();
    memcpy(dutVrf.data(), proc->VU.reg_file, dutVrf.size());
}

VecCsrs VectorChecker::readSpikeCsrs() const {
    auto &VU = proc->VU;
    VecCsrs c;
    c.vl = trunc(VU.vl->read());
    c.vtype = trunc(VU.vtype->read());
    c.vstart = trunc(VU.vstart->read());
    c.vxrm = VU.vxrm->read();
    c.vxsat = state->vxsat->read();
    c.vs = (state->mstatus->read() >> 9) & 3;
    return c;
}

void VectorChecker::setPolicy(const string &keyValues){
    istringstream f(keyValues);
    string kv;
    while(f >> kv){
        auto eq = kv.find('=');
        if(eq == string::npos) throw runtime_error("Bad policy item " + kv);
        policy.set(kv.substr(0, eq), kv.substr(eq + 1));
    }
}

//---------------------------------------------------------------- DUT events

void VectorChecker::vrfWrite(u32 reg, span<const u8> enable, span<const u8> data){
    if(reg >= 32 || enable.size() != vlenb || data.size() != vlenb)
        throw runtime_error("Bad vrf write event");
    for(u32 b = 0; b < vlenb; b++){
        if(!enable[b]) continue;
        evVrf[reg * vlenb + b] = data[b];
        evWritten[reg * vlenb + b] = 1;
    }
}

void VectorChecker::implicitCsr(u32 address, u64 value){
    switch(address){
    case CSR_VL: case CSR_VTYPE: case CSR_VSTART: case CSR_VXSAT: case CSR_VXRM:
        evImplicit[address] = trunc(value);
        break;
    default:
        failure(hart.context, hart.hartId, "Bad implicit vector CSR 0x%x\n", address);
    }
}

void VectorChecker::vsWrite(u64 value){
    evVs = true;
    evVsValue = value & 3;
}

void VectorChecker::explicitCsrWrite(u32 address, u64 value){
    evExplicit = true;
    evExplicitAddr = address;
    evExplicitValue = trunc(value);
}

void VectorChecker::resetEvents(){
    fill(evWritten.begin(), evWritten.end(), 0);
    evImplicit.clear();
    evVs = false;
    evExplicit = false;
}

//---------------------------------------------------------------- step hooks

void VectorChecker::beforeStep(bool trapStep){
    auto &VU = proc->VU;
    stepActive = true;
    this->trapStep = trapStep;
    decoded = false;
    executed = false;
    cur = VInsn();
    curText.clear();
    spikeLoads.clear();
    spikeStores.clear();
    loadMisses.clear();

    memcpy(preVrf.data(), VU.reg_file, preVrf.size());
    pre = readSpikeCsrs();
    for(int i = 0; i < 32; i++) preXpr[i] = state->XPR[i];
    prePc = state->pc;
    vpre.vlen = vlen;
    vpre.vl = pre.vl;
    vpre.vstart = pre.vstart;
    vpre.vlmax = VU.vlmax;
    vpre.sew = VU.vsew;
    vpre.lmul = VU.vflmul;
    vpre.vta = VU.vta;
    vpre.vma = VU.vma;
    vpre.vill = VU.vill;
    vpre.vrf = preVrf.data();

    if(policy.sync){
        // Invariant: after every checked instruction the DUT shadow equals Spike.
        if(memcmp(dutVrf.data(), preVrf.data(), preVrf.size()))
            failure(hart.context, hart.hartId, "VECTOR SHADOW DIVERGED: DUT VRF shadow differs from Spike before 0x%lx\n", prePc);
        if(dutCsr.vl != pre.vl || dutCsr.vtype != pre.vtype || dutCsr.vstart != pre.vstart || dutCsr.vxrm != pre.vxrm
           || dutCsr.vxsat != pre.vxsat || dutCsr.vs != pre.vs)
            failure(hart.context, hart.hartId, "VECTOR SHADOW DIVERGED: DUT vector CSR shadow differs from Spike before 0x%lx\n", prePc);
    }
    state->last_inst = insn_t(NO_INSN);
}

void VectorChecker::decodeCurrent(){
    if(decoded) return;
    decoded = true;
    reg_t bits = state->last_inst.bits();
    executed = bits != NO_INSN;
    if(!executed) return;
    curText = disasm->disassemble(state->last_inst);
    cur = vdecode(u32(bits), curText);
    // RV32 XPRs are sign-extended in Spike; addresses are zero-extended.
    vpre.xrs1 = trunc(preXpr[cur.rs1]);
}

bool VectorChecker::routesMemory(){
    if(!stepActive) return false;
    decodeCurrent();
    return executed && cur.isVectorMem();
}

// Element index of a Spike access (from vstart; consecutive for ff).
u64 VectorChecker::currentElement(u64 addr) const {
    if(cur.ff) return (addr - vpre.xrs1) / (cur.nf * cur.eewEnc / 8);
    return proc->VU.vstart->read();
}

bool VectorChecker::injectsFault(u64 addr){
    // Without sync, Spike keeps its own vl.
    if(!routesMemory() || !cur.ff || trapStep || !policy.ffTrimAny || !policy.sync) return false;
    auto it = evImplicit.find(CSR_VL);
    if(it == evImplicit.end() || it->second >= pre.vl) return false;
    // Trim to vl = 0 is illegal (norm:vector_ff_no_exception): checkCsrs reports it.
    if(it->second == 0) return false;
    // Make Spike trim where the DUT did.
    return currentElement(addr) >= it->second;
}

void VectorChecker::spikeLoad(u64 addr, u32 len, u8 *bytes){
    u64 elem = currentElement(addr);
    if(!hart.memory->vectorLoad(addr, len, bytes))
        loadMisses.push_back({addr, len, {}, elem});
    spikeLoads.push_back({addr, len, vector<u8>(bytes, bytes + len), elem});
}

void VectorChecker::spikeStore(u64 addr, u32 len, const u8 *bytes){
    spikeStores.push_back({addr, len, vector<u8>(bytes, bytes + len), currentElement(addr)});
}

//---------------------------------------------------------------- checks

void VectorChecker::fail(const string &cls, const string &detail) const {
    string where = executed ? format("pc=0x{:x} insn=0x{:08x} `{}`", prePc, cur.bits, curText)
                            : format("pc=0x{:x} (no instruction executed)", prePc);
    failure(hart.context, hart.hartId, cls + ": " + where + ": " + detail + "\n");
}

string VectorChecker::slotName(const VSlot &s) const {
    u32 reg = s.bit / vlen;
    u32 off = s.bit % vlen;
    if(s.bits == 1) return format("v{} mask bit {} ({})", reg, s.index, vclassName(s.cls));
    string seg = cur.nf > 1 && cur.isVectorMem() ? format(" field {}", s.field) : "";
    return format("v{} element {}{} bytes {}..{} ({})", reg, s.index, seg, off / 8, off / 8 + s.bits / 8 - 1, vclassName(s.cls));
}

void VectorChecker::checkExplicitCsr(bool trap){
    bool vecCsrInsn = executed && cur.csr && isVectorCsrAddr(cur.csrAddr);
    if(!vecCsrInsn || trap){
        if(evExplicit) fail("VCSR WRITE SPAWNED", format("DUT reported a write of CSR 0x{:03x}", evExplicitAddr));
        return;
    }
    if(cur.csrWrites && !evExplicit) fail("VCSR WRITE MISSING", format("no write of CSR 0x{:03x} reported", cur.csrAddr));
    if(!cur.csrWrites && evExplicit) fail("VCSR WRITE SPAWNED", format("the instruction does not write CSR 0x{:03x}", cur.csrAddr));
    if(!evExplicit) return;
    if(evExplicitAddr != cur.csrAddr)
        fail("VCSR WRITE ADDRESS", format("DUT=0x{:03x} REF=0x{:03x}", evExplicitAddr, cur.csrAddr));
    auto post = readSpikeCsrs();
    u64 ref;
    switch(cur.csrAddr){
    case CSR_VSTART: ref = post.vstart; dutCsr.vstart = evExplicitValue; break;
    case CSR_VXSAT: ref = post.vxsat; dutCsr.vxsat = evExplicitValue; break;
    case CSR_VXRM: ref = post.vxrm; dutCsr.vxrm = evExplicitValue; break;
    case CSR_VCSR:
        ref = (post.vxrm << 1) | post.vxsat;
        dutCsr.vxrm = (evExplicitValue >> 1) & 3;
        dutCsr.vxsat = evExplicitValue & 1;
        break;
    default:
        fail("VCSR WRITE SPAWNED", format("CSR 0x{:03x} is read-only", cur.csrAddr));
    }
    if(evExplicitValue != ref)
        fail("VCSR WRITE MISMATCH", format("CSR 0x{:03x} DUT=0x{:x} REF=0x{:x}", cur.csrAddr, evExplicitValue, ref));
}

void VectorChecker::checkCsrs(VecCsrs &post){
    VecCsrs dutPre = dutCsr;
    for(auto [address, value] : evImplicit){
        switch(address){
        case CSR_VL: dutCsr.vl = value; break;
        case CSR_VTYPE: dutCsr.vtype = value; break;
        case CSR_VSTART: dutCsr.vstart = value; break;
        case CSR_VXSAT: dutCsr.vxsat = value; break;
        case CSR_VXRM: dutCsr.vxrm = value; break;
        }
    }
    if(evVs) dutCsr.vs = evVsValue;

    // Fault-only-first trim without a fault: Spike's vl >= the DUT's unless
    // Spike met a real fault earlier.
    if(executed && cur.ff && dutCsr.vl != post.vl && policy.ffTrimAny && dutCsr.vl < pre.vl){
        if(pre.vstart == 0 && pre.vl > 0 && dutCsr.vl == 0)
            fail("FF TRIM TO ZERO", "fault-only-first must process at least one element when vstart = 0 and vl > 0 (norm:vector_ff_no_exception)");
        if(dutCsr.vl > post.vl)
            fail("FF TRIM PAST FAULT", format("DUT vl={} but the element at {} faults", dutCsr.vl, post.vl));
        if(dutCsr.vl < pre.vstart)
            fail("FF TRIM PAST FAULT", format("DUT vl={} is below vstart={}", dutCsr.vl, pre.vstart));
        // Elements [DUT vl, Spike vl) are all inactive: a legal, checked difference.
        if(policy.sync) proc->VU.vl->write_raw(dutCsr.vl);
        // Check against the DUT's processed set, also without sync.
        post.vl = dutCsr.vl;
    }

    struct Item { const char *cls; u64 dPre, dPost, rPre, rPost; };
    Item items[] = {
        {"VL MISMATCH", dutPre.vl, dutCsr.vl, pre.vl, post.vl},
        {"VTYPE MISMATCH", dutPre.vtype, dutCsr.vtype, pre.vtype, post.vtype},
        {"VSTART MISMATCH", dutPre.vstart, dutCsr.vstart, pre.vstart, post.vstart},
        {"VXRM MISMATCH", dutPre.vxrm, dutCsr.vxrm, pre.vxrm, post.vxrm},
        {"VXSAT MISMATCH", dutPre.vxsat, dutCsr.vxsat, pre.vxsat, post.vxsat},
        {"VS MISMATCH", dutPre.vs, dutCsr.vs, pre.vs, post.vs},
    };
    for(auto &i : items){
        bool changed = i.dPre != i.dPost || i.rPre != i.rPost;
        if(changed && i.dPost != i.rPost)
            fail(i.cls, format("DUT=0x{:x} REF=0x{:x} (before: DUT=0x{:x} REF=0x{:x})", i.dPost, i.rPost, i.dPre, i.rPre));
    }
}

void VectorChecker::checkMemory(bool trap, const VecCsrs &post){
    auto *mem = hart.memory;
    // Bytes of the faulting segment that the policy says are not accessed.
    bool dropFaultingSegment = trap && policy.segPartialNone && cur.nf > 1;
    auto dropped = [&](const SpikeAccess &a){ return dropFaultingSegment && a.elem == post.vstart; };

    // Stores: the DUT's bytes must equal Spike's.
    map<u64, u8> dutBytes, refBytes;
    for(auto &s : mem->pendingStores){
        for(size_t b = 0; b < s->len; b++) if(s->enable[b]) dutBytes[s->addr + b] = s->bytes[b];
    }
    for(auto &s : spikeStores){
        if(dropped(s)) continue;
        for(u32 b = 0; b < s.len; b++) refBytes[s.addr + b] = s.data[b];
    }
    for(auto [a, v] : refBytes){
        auto it = dutBytes.find(a);
        if(it == dutBytes.end()) fail("STORE MISSING", format("byte 0x{:x} = 0x{:02x} not stored", a, v));
        if(it->second != v) fail("STORE DATA MISMATCH", format("byte 0x{:x} DUT=0x{:02x} REF=0x{:02x}", a, it->second, v));
    }
    for(auto [a, v] : dutBytes){
        if(!refBytes.count(a)) fail("STORE EXTRA", format("DUT stored byte 0x{:x} = 0x{:02x}, which no processed element writes", a, v));
    }

    // Loads: processed bytes must come from DUT loads; extra RAM reads are allowed.
    for(auto &m : loadMisses){
        if(dropped(m)) continue;
        if(cur.ff && !trap && policy.ffTrimAny && m.elem >= post.vl) continue;
        fail("VECTOR LOAD MISSING", format("element {} at 0x{:x} ({} bytes) is not covered by a DUT load", m.elem, m.addr, m.len));
    }
    for(auto &l : mem->pendingLoads){
        if(!hart.sif->isMemRange(l->addr, l->len))
            fail("VECTOR LOAD NOT IN MEMORY", format("DUT load at 0x{:x} ({} bytes) is outside the idempotent memory regions", l->addr, l->len));
        if(!l->used) extraLoadBytes += l->len;
    }
}

bool VectorChecker::computeAlt(bool vlenForm, vector<u8> &out){
    // Re-run on Spike's pre-state with another vl/vtype (norm:vreg_mask_tail_op).
    // Everything it touches is restored.
    auto &VU = proc->VU;
    size_t size = 32 * vlenb;
    u8 *rf = (u8*)VU.reg_file;
    vector<u8> saved(rf, rf + size);
    reg_t sVl = VU.vl->read(), sVtype = VU.vtype->read(), sVstart = VU.vstart->read();
    auto sVsew = VU.vsew; auto sVflmul = VU.vflmul; auto sVlmax = VU.vlmax;
    auto sVta = VU.vta; auto sVma = VU.vma; auto sVill = VU.vill;
    reg_t sMstatus = state->mstatus->read();
    auto sLog = state->log_reg_write;
    reg_t sPc = state->pc;
    bool ok = true;

    memcpy(rf, preVrf.data(), size);
    VU.vstart->write_raw(0);
    if(vlenForm){
        VU.vsew = 8; VU.vflmul = 8; VU.vlmax = vlen; VU.vill = false;
        VU.vtype->write_raw((pre.vtype & 0xc0) | 3);
        VU.vl->write_raw(vlen);
    } else {
        VU.vsew = vpre.sew; VU.vflmul = vpre.lmul; VU.vlmax = vpre.vlmax; VU.vill = vpre.vill;
        VU.vta = vpre.vta; VU.vma = vpre.vma;
        VU.vtype->write_raw(pre.vtype);
        VU.vl->write_raw(vpre.vlmax);
    }
    try {
        auto fetch = proc->get_mmu()->access_icache(prePc)->data;
        fetch.func(proc, fetch.insn, prePc);
    } catch(...) {
        ok = false;
    }
    out.assign(rf, rf + size);

    memcpy(rf, saved.data(), size);
    VU.vl->write_raw(sVl); VU.vtype->write_raw(sVtype); VU.vstart->write_raw(sVstart);
    VU.vsew = sVsew; VU.vflmul = sVflmul; VU.vlmax = sVlmax; VU.vta = sVta; VU.vma = sVma; VU.vill = sVill;
    if(state->mstatus->read() != sMstatus) state->mstatus->unlogged_backdoor_write(sMstatus);
    state->log_reg_write = sLog;
    state->pc = sPc;
    return ok;
}

// Exception causes after which a vector load leaves a partial result.
static bool isMemoryTrap(u32 code){
    return code == 3 || code == 4 || code == 5 || code == 13 || code == 21;
}

void VectorChecker::checkVrf(bool trap, u32 code, const VecCsrs &post){
    u8 *ref = (u8*)proc->VU.reg_file;
    size_t size = 32 * vlenb;
    vector<u8> dut = dutVrf;
    for(size_t b = 0; b < size; b++) if(evWritten[b]) dut[b] = evVrf[b];

    vector<VSlot> slots;
    bool partial = trap && cur.load && isMemoryTrap(code);
    if(executed && cur.vector && (!trap || partial)){
        VOutcome out{partial, post.vstart, post.vl};
        vbuildSlots(cur, vpre, out, slots);
    }

    vector<u8> covered(32 * vlen, 0);
    vector<u8> altVlmax, altVlen;
    bool haveVlmax = false, haveVlen = false, okVlmax = false, okVlen = false;
    vector<const VSlot*> syncs;

    for(auto &s : slots){
        for(u32 b = 0; b < s.bits; b++) covered[s.bit + b] = 1;
        u64 dv = vslotGet(dut.data(), s), rv = vslotGet(ref, s), ov = vslotGet(preVrf.data(), s);
        // Policy "none": no field of the faulting segment changes
        // (norm:vector_ls_seg_partial_access).
        if(s.cls == VClass::SegPartial && policy.segPartialNone && dv != ov){
            u32 w = (s.bits + 3) / 4;
            fail("VRF SEGMENT PARTIAL MISMATCH", format("{}: DUT=0x{:0{}x} OLD=0x{:0{}x} (policy segPartialNone)", slotName(s), dv, w, ov, w));
        }
        if(dv == rv) continue;
        bool ones = dv == vslotOnes(s), old = dv == ov;
        bool ok = false;
        const char *cls = "VRF ELEMENT MISMATCH";
        switch(s.cls){
        case VClass::Active:
            cls = (old && rv != ov) ? "VRF WRITE MISSING" : "VRF ELEMENT MISMATCH";
            break;
        case VClass::Prestart: cls = "VRF PRESTART WRITE"; break;
        case VClass::Unchanged: cls = "VRF SLIDEUP UNCHANGED WRITE"; break;
        case VClass::NoBody: cls = "VRF WRITE WITHOUT BODY"; break;
        case VClass::Faulting: cls = "VRF WRITE PAST TRAP"; break;
        case VClass::Inactive:
            ok = policy.agnostic && vpre.vma && (old || ones);
            cls = policy.agnostic && vpre.vma ? "VRF ILLEGAL AGNOSTIC VALUE" : "VRF INACTIVE WRITE";
            break;
        case VClass::Tail:
            ok = policy.agnostic && vpre.vta && (old || ones);
            cls = policy.agnostic && vpre.vta ? "VRF ILLEGAL AGNOSTIC VALUE" : "VRF TAIL WRITE";
            break;
        case VClass::MaskLdTail:
            ok = policy.agnostic && (old || ones);
            cls = policy.agnostic ? "VRF ILLEGAL AGNOSTIC VALUE" : "VRF TAIL WRITE";
            break;
        case VClass::MaskTail:
            cls = policy.agnostic ? "VRF ILLEGAL AGNOSTIC VALUE" : "VRF TAIL WRITE";
            if(!policy.agnostic) break;
            ok = old || ones;
            if(!ok){
                if(!haveVlmax){ haveVlmax = true; okVlmax = computeAlt(false, altVlmax); }
                ok = okVlmax && dv == vslotGet(altVlmax.data(), s);
            }
            if(!ok && cur.maskAltVlen){
                if(!haveVlen){ haveVlen = true; okVlen = computeAlt(true, altVlen); }
                ok = okVlen && dv == vslotGet(altVlen.data(), s);
            }
            break;
        case VClass::PastTrap:
            ok = policy.loadPastTrapAny;
            cls = "VRF WRITE PAST TRAP";
            break;
        case VClass::FfSpurious:
            ok = policy.ffTrimAny;
            cls = "VRF FF SPURIOUS WRITE";
            break;
        case VClass::SegPartial:
            ok = policy.segPartialNone && old;
            cls = "VRF SEGMENT PARTIAL MISMATCH";
            break;
        }
        if(!ok){
            u32 w = s.bits == 1 ? 1 : (s.bits + 3) / 4;
            fail(cls, format("{}: DUT=0x{:0{}x} REF=0x{:0{}x} OLD=0x{:0{}x}", slotName(s), dv, w, rv, w, ov, w));
        }
        syncs.push_back(&s);
    }

    // Outside the destination, nothing may change on either side.
    for(size_t byte = 0; byte < size; byte++){
        u8 dutDiff = dut[byte] ^ dutVrf[byte], refDiff = ref[byte] ^ preVrf[byte];
        for(u32 bit = 0; bit < 8; bit++){
            if(covered[byte * 8 + bit]) continue;
            if((refDiff >> bit) & 1)
                fail("VRF CHECKER SHAPE ERROR", format("Spike changed v{} byte {} outside the computed destination", byte / vlenb, byte % vlenb));
            if((dutDiff >> bit) & 1)
                fail("VRF WRITE OUTSIDE GROUP", format("v{} byte {}: DUT=0x{:02x} OLD=0x{:02x}", byte / vlenb, byte % vlenb, dut[byte], dutVrf[byte]));
        }
    }

    if(policy.sync){
        for(auto *s : syncs) vslotSet(ref, *s, vslotGet(dut.data(), *s));
    }
    dutVrf = dut;
}

void VectorChecker::afterStep(bool trap, bool interrupt, u32 code){
    stepActive = false;
    decodeCurrent();
    auto *mem = hart.memory;
    try {
        VecCsrs post = readSpikeCsrs();
        // The pinned FF loop does not write vstart before a debug data trigger.
        bool ffWatchpoint = trap && !interrupt && code == 3 && executed && cur.ff;
        if(ffWatchpoint){
            u64 addr = trunc((state->prv == PRV_M ? state->mtval : state->stval)->read());
            u64 offset = trunc(addr - vpre.xrs1);
            u64 stride = cur.nf * cur.eewEnc / 8;
            u64 index = offset / stride;
            if(index < pre.vstart || index >= pre.vl || offset % (cur.eewEnc / 8)
               || (!cur.vm && !(preVrf[index / 8] & (1u << (index % 8)))))
                fail("FF WATCHPOINT ADDRESS", "breakpoint address is outside the active load elements");
            post.vstart = index;
            post.vs = 3;
        }
        checkExplicitCsr(trap);
        checkCsrs(post);
        if(executed && cur.isVectorMem()) checkMemory(trap && !interrupt, post);
        checkVrf(trap && !interrupt, code, post);
        if(ffWatchpoint && policy.sync){
            proc->VU.vstart->write_raw(post.vstart);
            state->sstatus->dirty(SSTATUS_VS);
        }
    } catch(...) {
        resetEvents();
        throw;
    }
    if(executed && cur.isVectorMem()){
        // The instruction's stores reach the in-flight loads as scalar stores do.
        for(auto &s : mem->pendingStores) mem->bypassInflight(*s);
        mem->releasePending();
    }
    resetEvents();
}

string VectorChecker::formatContext() const {
    stringstream ss;
    auto &VU = proc->VU;
    ss << "vector state (Spike / DUT shadow):\n";
    auto c = readSpikeCsrs();
    ss << format("  vl={}/{} vtype=0x{:x}/0x{:x} vstart={}/{} vxrm={}/{} vxsat={}/{} vs={}/{}\n",
                 c.vl, dutCsr.vl, c.vtype, dutCsr.vtype, c.vstart, dutCsr.vstart, c.vxrm, dutCsr.vxrm,
                 c.vxsat, dutCsr.vxsat, c.vs, dutCsr.vs);
    ss << "  policy: " << policy.describe() << "\n";
    for(u32 r = 0; r < 32; r++){
        const u8 *s = (const u8*)VU.reg_file + r * vlenb;
        const u8 *d = dutVrf.data() + r * vlenb;
        ss << format("  v{:<2} {}", r, hexBytes(s, vlenb));
        if(memcmp(s, d, vlenb)) ss << " DUT " << hexBytes(d, vlenb);
        ss << "\n";
    }
    if(extraLoadBytes) ss << format("  extra DUT load bytes so far: {}\n", extraLoadBytes);
    return ss.str();
}
