/*
 * vshape.cpp: see vshape.hpp.
 */

#include "vshape.hpp"
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cstring>

using namespace std;

static bool startsWith(const string &s, const char *p){ return s.rfind(p, 0) == 0; }

void VecPolicy::set(const string &key, const string &value){
    bool v = value == "1" || value == "true" || value == "yes";
    if(!v && !(value == "0" || value == "false" || value == "no"))
        throw runtime_error("Bad policy value " + key + "=" + value);
    if(key == "agnostic") agnostic = v;
    else if(key == "ffTrimAny") ffTrimAny = v;
    else if(key == "loadPastTrapAny") loadPastTrapAny = v;
    else if(key == "segPartialNone") segPartialNone = v;
    else if(key == "ioWideFault") ioWideFault = v;
    else if(key == "sync") sync = v;
    else throw runtime_error("Unknown policy key " + key);
}

string VecPolicy::describe() const {
    stringstream ss;
    ss << "agnostic=" << agnostic << " ffTrimAny=" << ffTrimAny << " loadPastTrapAny=" << loadPastTrapAny
       << " segPartialNone=" << segPartialNone << " ioWideFault=" << ioWideFault << " sync=" << sync;
    return ss.str();
}

const char *vclassName(VClass c){
    switch(c){
    case VClass::Prestart: return "prestart";
    case VClass::Unchanged: return "slideup-unchanged";
    case VClass::NoBody: return "no-body";
    case VClass::Active: return "body-active";
    case VClass::Inactive: return "body-inactive";
    case VClass::Tail: return "tail";
    case VClass::MaskTail: return "mask-tail";
    case VClass::MaskLdTail: return "vlm-tail";
    case VClass::Faulting: return "faulting";
    case VClass::PastTrap: return "past-trap";
    case VClass::SegPartial: return "faulting-segment";
    case VClass::FfSpurious: return "ff-trimmed";
    }
    return "?";
}

bool isVectorCsrAddr(u32 a){
    return a == 0x008 || a == 0x009 || a == 0x00A || a == 0x00F || a == 0xC20 || a == 0xC21 || a == 0xC22;
}

VInsn vdecode(u32 bits, const string &mnemonic){
    VInsn d;
    d.bits = bits;
    d.name = mnemonic.substr(0, mnemonic.find(' '));
    u32 opcode = bits & 0x7f;
    u32 funct3 = (bits >> 12) & 7;
    d.vd = (bits >> 7) & 0x1f;
    d.rs1 = (bits >> 15) & 0x1f;
    d.rs2 = (bits >> 20) & 0x1f;
    d.vm = (bits >> 25) & 1;

    if((opcode == 0x07 || opcode == 0x27) && (funct3 == 0 || funct3 >= 5)){
        static const u32 eews[8] = {8, 0, 0, 0, 0, 16, 32, 64};
        d.vector = true;
        d.load = opcode == 0x07;
        d.store = !d.load;
        d.eewEnc = eews[funct3];
        d.mop = (bits >> 26) & 3;
        d.nf = ((bits >> 29) & 7) + 1;
        d.lumop = d.rs2;
        d.indexed = d.mop == 1 || d.mop == 3;
        d.whole = d.mop == 0 && d.lumop == 8;
        d.maskLdSt = d.mop == 0 && d.lumop == 11;
        d.ff = d.load && d.mop == 0 && d.lumop == 16;
        if(d.load) d.kind = d.whole ? VInsn::WHOLE : d.maskLdSt ? VInsn::MASKLD : VInsn::NORMAL;
        if(d.whole) d.wholeRegs = d.nf;
        return d;
    }

    if(opcode == 0x73 && funct3 != 0 && funct3 != 4){
        d.csr = true;
        d.csrAddr = bits >> 20;
        // csrrw/csrrwi always write; set/clear write unless rs1/uimm is zero.
        d.csrWrites = (funct3 & 3) == 1 || d.rs1 != 0;
        return d;
    }

    if(opcode != 0x57) return d;
    if(funct3 == 7){
        d.vset = true;
        return d;
    }
    d.vector = true;
    const string &n = d.name;
    auto in = [&](initializer_list<const char*> l){ for(auto p : l) if(n == p) return true; return false; };

    if(in({"vcpop.m", "vfirst.m", "vmv.x.s", "vfmv.f.s"})){
        d.kind = VInsn::NONE;
    } else if(n == "vmv.s.x" || n == "vfmv.s.f"){
        d.kind = VInsn::ELEM0;
    } else if(startsWith(n, "vwred")){
        d.kind = VInsn::ELEM0; d.eewMul = 2;
    } else if(startsWith(n, "vred")){
        d.kind = VInsn::ELEM0;
    } else if(n.size() == 7 && startsWith(n, "vmv") && n[4] == 'r' && n.substr(5) == ".v"){
        d.kind = VInsn::WHOLE;
        d.wholeRegs = n[3] - '0';
    } else if(n == "vcompress.vm"){
        d.kind = VInsn::COMPRESS;
    } else if(in({"vmsbf.m", "vmsif.m", "vmsof.m"})){
        d.kind = VInsn::MASK; d.maskAltVlen = true;
    } else if(in({"vmand.mm", "vmnand.mm", "vmandn.mm", "vmxor.mm", "vmor.mm", "vmnor.mm", "vmorn.mm", "vmxnor.mm"})){
        d.kind = VInsn::MASK; d.maskAltVlen = true; d.allActive = true;
    } else if(startsWith(n, "vmadc") || startsWith(n, "vmsbc")){
        d.kind = VInsn::MASK; d.allActive = true;
    } else if(startsWith(n, "vmseq") || startsWith(n, "vmsne") || startsWith(n, "vmslt") || startsWith(n, "vmsle")
              || startsWith(n, "vmsgt")){
        d.kind = VInsn::MASK;
    } else if(startsWith(n, "vw")){
        d.kind = VInsn::NORMAL; d.eewMul = 2;
    } else if(startsWith(n, "vadc") || startsWith(n, "vsbc") || startsWith(n, "vmerge")){
        d.kind = VInsn::NORMAL; d.allActive = true;
    } else if(n == "vslideup.vx" || n == "vslideup.vi"){
        d.kind = VInsn::NORMAL;
        d.slideupX = n == "vslideup.vx";
        d.slideupI = !d.slideupX;
    } else {
        d.kind = VInsn::NORMAL;
    }
    return d;
}

u64 vslotGet(const u8 *vrf, const VSlot &s){
    if(s.bits == 1) return vmaskBit(vrf, s.bit);
    u64 v = 0;
    for(u32 b = 0; b < s.bits / 8; b++) v |= u64(vrf[s.bit / 8 + b]) << (8 * b);
    return v;
}

void vslotSet(u8 *vrf, const VSlot &s, u64 value){
    if(s.bits == 1){
        u8 &byte = vrf[s.bit / 8];
        byte = (byte & ~(1 << (s.bit % 8))) | ((value & 1) << (s.bit % 8));
        return;
    }
    for(u32 b = 0; b < s.bits / 8; b++) vrf[s.bit / 8 + b] = value >> (8 * b);
}

namespace {

struct Builder {
    const VInsn &d;
    const VPre &pre;
    const VOutcome &out;
    vector<VSlot> &slots;

    bool active(u64 i) const {
        return d.vm || d.allActive || vmaskBit(pre.vrf, i);
    }

    void add(u32 reg, u32 offsetBits, u32 bits, u64 index, u32 field, VClass cls){
        slots.push_back(VSlot{reg * pre.vlen + offsetBits, bits, index, field, cls});
    }

    // Elements [0, count) of `fields` register groups of EEW `eew`, EMUL `emul`.
    // `cls(i, f)` gives the class of element i of field f.
    template<typename F>
    void group(u32 base, u32 eew, double emul, u32 fields, u64 count, F cls){
        u32 regsPerField = emul < 1 ? 1 : u32(emul);
        u32 perReg = pre.vlen / eew;
        for(u32 f = 0; f < fields; f++){
            for(u64 i = 0; i < count; i++){
                u32 reg = base + f * regsPerField + u32(i / perReg);
                if(reg >= 32) continue; // reserved encodings trap before writing
                add(reg, u32(i % perReg) * eew, eew, i, f, cls(i, f));
            }
        }
    }

    // Elements of a vl/vstart-governed group: body, tail, prestart.
    VClass bodyClass(u64 i, u64 vstart, u64 vl) const {
        if(vstart >= vl) return VClass::NoBody;
        if(i < vstart) return VClass::Prestart;
        if(i < vl) return active(i) ? VClass::Active : VClass::Inactive;
        return VClass::Tail;
    }

    void build(){
        const u64 vl = pre.vl, vstart = pre.vstart;
        switch(d.kind){
        case VInsn::NONE:
            return;
        case VInsn::NORMAL: {
            u32 eew; double emul; u32 fields = 1;
            if(d.load){
                eew = d.indexed ? pre.sew : d.eewEnc;
                emul = double(eew) / pre.sew * pre.lmul;
                fields = d.nf;
            } else {
                eew = pre.sew * d.eewMul;
                emul = pre.lmul * d.eewMul;
            }
            // Includes the fractional-LMUL tail up to VLEN/EEW.
            u64 count = emul < 1 ? pre.vlen / eew : u64(emul * pre.vlen / eew);
            u64 offset = 0;
            if(d.slideupX) offset = pre.xrs1;
            if(d.slideupI) offset = d.rs1;
            group(d.vd, eew, emul, fields, count, [&](u64 i, u32 f) -> VClass {
                if(d.load && out.trap){
                    if(vstart >= vl) return VClass::NoBody;
                    if(i < vstart) return VClass::Prestart;
                    if(i >= vl) return VClass::Tail;
                    if(i < out.trapVstart) return active(i) ? VClass::Active : VClass::Inactive;
                    if(!active(i)) return VClass::Inactive;
                    if(i == out.trapVstart) return fields > 1 ? VClass::SegPartial : VClass::Faulting;
                    return VClass::PastTrap;
                }
                if(d.ff && out.postVl < vl){
                    if(vstart >= vl) return VClass::NoBody;
                    if(i < vstart) return VClass::Prestart;
                    if(i < out.postVl) return active(i) ? VClass::Active : VClass::Inactive;
                    if(i < vl) return active(i) ? VClass::FfSpurious : VClass::Inactive;
                    return VClass::Tail;
                }
                VClass c = bodyClass(i, vstart, vl);
                // vslideup: elements below max(vstart, OFFSET) are unchanged.
                if((d.slideupX || d.slideupI) && c != VClass::NoBody && c != VClass::Tail && i < offset)
                    return VClass::Unchanged;
                return c;
            });
        } break;
        case VInsn::MASK: {
            // One register, one bit per element; tail up to VLEN
            // (norm:vreg_mask_tail_agn).
            for(u64 i = 0; i < pre.vlen; i++){
                VClass c;
                if(vstart >= vl) c = VClass::NoBody;
                else if(i < vstart) c = VClass::Prestart;
                else if(i < vl) c = active(i) ? VClass::Active : VClass::Inactive;
                else c = VClass::MaskTail;
                add(d.vd, u32(i), 1, i, 0, c);
            }
        } break;
        case VInsn::ELEM0: {
            // Element 0 of vd; elements 1 .. VLEN/EEW-1 are tail
            // (norm:vreduction_tail_policy, vmv.s.x).  vl = 0: no update.
            u32 eew = pre.sew * d.eewMul;
            bool body = vstart < vl;
            for(u64 i = 0; i < pre.vlen / eew; i++){
                VClass c = !body ? VClass::NoBody : i == 0 ? VClass::Active : VClass::Tail;
                add(d.vd, u32(i) * eew, eew, i, 0, c);
            }
        } break;
        case VInsn::WHOLE: {
            u32 eew = d.load ? d.eewEnc : pre.sew;
            u64 evl = u64(d.wholeRegs) * pre.vlen / eew;
            group(d.vd, eew, d.wholeRegs, 1, evl, [&](u64 i, u32) -> VClass {
                if(vstart >= evl) return VClass::NoBody;
                if(i < vstart) return VClass::Prestart;
                if(out.trap && d.load) return i < out.trapVstart ? VClass::Active : i == out.trapVstart ? VClass::Faulting : VClass::PastTrap;
                return VClass::Active;
            });
        } break;
        case VInsn::MASKLD: {
            // vlm.v: EEW = 8, evl = ceil(vl/8), always tail agnostic
            // (norm:vector_ls_unit_stride_mask).
            u64 evl = (vl + 7) / 8;
            for(u64 i = 0; i < pre.vlen / 8; i++){
                VClass c;
                if(vstart >= evl) c = VClass::NoBody;
                else if(i < vstart) c = VClass::Prestart;
                else if(i >= evl) c = VClass::MaskLdTail;
                else if(out.trap) c = i < out.trapVstart ? VClass::Active : i == out.trapVstart ? VClass::Faulting : VClass::PastTrap;
                else c = VClass::Active;
                add(d.vd, u32(i) * 8, 8, i, 0, c);
            }
        } break;
        case VInsn::COMPRESS: {
            // Packed elements [0, popcount) are the body, the rest is tail
            // (norm:vcompress_op).
            u64 packed = 0;
            for(u64 i = 0; i < vl; i++) packed += vmaskBit(pre.vrf, u64(d.rs1) * pre.vlen + i);
            u32 eew = pre.sew;
            u64 count = pre.lmul < 1 ? pre.vlen / eew : u64(pre.lmul * pre.vlen / eew);
            group(d.vd, eew, pre.lmul, 1, count, [&](u64 i, u32) -> VClass {
                if(vstart >= vl) return VClass::NoBody;
                return i < packed ? VClass::Active : VClass::Tail;
            });
        } break;
        }
    }
};

}

void vbuildSlots(const VInsn &insn, const VPre &pre, const VOutcome &out, vector<VSlot> &slots){
    slots.clear();
    Builder{insn, pre, out, slots}.build();
}
