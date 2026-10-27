// Generates RVLS traces from a Spike run (no Hart or VectorChecker).
#include <sys/syscall.h>
#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include "CLI11.hpp"
#include "elf.hpp"
#include "memory.hpp"
#include "processor.h"
#include "mmu.h"
#include "simif.h"
#include "disasm.h"
#include "vshape.hpp"

using namespace std;

namespace {
string hexBytes(const u8 *p, size_t n) {
    string out;
    for(size_t i = n; i-- > 0;) out += format("{:02x}", p[i]);
    return out;
}
string byteMask(const vector<u8> &enable) {
    string out((enable.size() + 3) / 4, '0');
    for(size_t n = 0; n < out.size(); ++n) {
        unsigned v = 0;
        for(unsigned b = 0; b < 4 && n * 4 + b < enable.size(); ++b)
            v |= unsigned(enable[n * 4 + b] != 0) << b;
        out[out.size() - 1 - n] = "0123456789abcdef"[v];
    }
    return out;
}
u64 number(const string &s) {
    size_t end = 0;
    if(s.empty() || s[0] == '-') throw runtime_error("Bad unsigned number: " + s);
    u64 v = stoull(s, &end, 0);
    if(end != s.size()) throw runtime_error("Bad number: " + s);
    return v;
}

struct Region { bool io; u64 base, size; };
struct Access {
    bool store, io;
    u64 addr, element;
    vector<u8> data, old;
};

// nullptr routes all data accesses through these callbacks.
class GeneratorSim final : public simif_t {
public:
    Memory memory;
    vector<Region> regions;
    vector<Access> accesses;
    cfg_t cfg;
    map<size_t, processor_t*> harts;
    map<u64, string> symbols;
    processor_t *proc = nullptr;
    VInsn current;
    u64 base = 0;
    optional<u64> trim;
    u64 injected = 0;
    bool ioWide = false;
    u64 ioInjected = 0;

    GeneratorSim() { debug_mmu = nullptr; }
    const Region *region(u64 addr, size_t len) const {
        if(!len || addr > UINT32_MAX || len - 1 > UINT32_MAX - addr) return nullptr;
        for(const auto &r : regions)
            if(addr >= r.base && addr - r.base < r.size && len <= r.size - (addr - r.base)) return &r;
        return nullptr;
    }
    u64 element(u64 addr) const {
        if(current.ff) return (addr - base) / (current.nf * current.eewEnc / 8);
        return current.isVectorMem() ? proc->VU.vstart->read() : 0;
    }
    // A vector IO element wider than 4 bytes takes an access fault (fault-only-first trims).
    bool wideIoFault(u64 addr, size_t len) {
        auto r = region(addr, len);
        if(!ioWide || !current.isVectorMem() || len <= 4 || !r || !r->io) return false;
        ++ioInjected;
        return true;
    }
    char *addr_to_mem(reg_t) override { return nullptr; }
    bool reservable(reg_t addr) override { auto r = region(addr, 1); return r && !r->io; }
    bool mmio_fetch(reg_t addr, size_t len, u8 *bytes) override {
        auto r = region(addr, len);
        if(!r || r->io) return false;
        memory.read(addr, len, bytes);
        return true;
    }
    bool mmio_mmu(reg_t, size_t, u8*) override {
        throw runtime_error("tracegen: page-table walks are not supported");
    }
    bool mmio_load(reg_t addr, size_t len, u8 *bytes) override {
        // Inject before touching IO or memory: trim has no access at/past n.
        if(current.ff && trim && element(addr) >= *trim) { ++injected; return false; }
        if(wideIoFault(addr, len)) return false;
        auto r = region(addr, len);
        if(!r) return false;
        memory.read(addr, len, bytes);
        accesses.push_back({false, r->io, addr, element(addr), vector<u8>(bytes, bytes + len), {}});
        return true;
    }
    bool mmio_store(reg_t addr, size_t len, const u8 *bytes) override {
        if(wideIoFault(addr, len)) return false;
        auto r = region(addr, len);
        if(!r) return false;
        vector<u8> old(len);
        memory.read(addr, len, old.data());
        accesses.push_back({true, r->io, addr, element(addr), vector<u8>(bytes, bytes + len), old});
        memory.write(addr, len, const_cast<u8*>(bytes));
        return true;
    }
    void proc_reset(unsigned) override {}
    const cfg_t &get_cfg() const override { return cfg; }
    const map<size_t, processor_t*> &get_harts() const override { return harts; }
    const char *get_symbol(uint64_t addr) override {
        auto it = symbols.find(addr);
        return it == symbols.end() ? nullptr : it->second.c_str();
    }
};

struct Snapshot {
    vector<u8> vrf;
    map<u32, u64> csrs;
    u64 vs;
    VPre pre;
    explicit Snapshot(processor_t &p) {
        auto &v = p.VU;
        auto s = p.get_state();
        const u8 *rf = static_cast<const u8*>(v.reg_file);
        vrf.assign(rf, rf + 32 * v.VLEN / 8);
        u64 mask = p.get_xlen() == 32 ? 0xffffffffull : ~0ull;
        for(u32 a : {CSR_VSTART, CSR_VXSAT, CSR_VXRM, CSR_VCSR, CSR_VL, CSR_VTYPE, CSR_VLENB})
            csrs[a] = s->csrmap.at(a)->read() & mask;
        vs = (s->mstatus->read() >> 9) & 3;
        pre.vlen = v.VLEN; pre.vl = csrs.at(CSR_VL); pre.vstart = csrs.at(CSR_VSTART);
        pre.vlmax = v.vlmax; pre.sew = v.vsew; pre.lmul = v.vflmul;
        pre.vta = v.vta; pre.vma = v.vma; pre.vill = v.vill;
        pre.vrf = vrf.data();
    }
};

map<string, u64> readSymbols(Elf &elf, GeneratorSim &sim) {
    map<string, u64> result;
    for(auto &section : elf.reader.sections) {
        if(section->get_type() != SHT_SYMTAB) continue;
        ELFIO::symbol_section_accessor symbols(elf.reader, section.get());
        for(size_t n = 0; n < symbols.get_symbols_num(); ++n) {
            string name; ELFIO::Elf64_Addr value; ELFIO::Elf_Xword size;
            unsigned char bind, type, other; ELFIO::Elf_Half index;
            symbols.get_symbol(n, name, value, size, bind, type, index, other);
            if(name.empty() || index == SHN_UNDEF) continue;
            result[name] = value;
            sim.symbols.try_emplace(value, name);
        }
    }
    return result;
}

void readRegions(const string &path, GeneratorSim &sim, u64 limit) {
    ifstream in(path);
    if(!in) throw runtime_error("Cannot open region file " + path);
    string line;
    while(getline(in, line)) {
        line = line.substr(0, line.find('#'));
        istringstream f(line);
        string kind, base, size, extra;
        if(!(f >> kind)) continue;
        if(!(f >> base >> size) || (f >> extra) || (kind != "mem" && kind != "io"))
            throw runtime_error("Bad region: " + line);
        Region r{kind == "io", number(base), number(size)};
        if(!r.size || r.base > limit || r.size - 1 > limit - r.base)
            throw runtime_error("Regions must fit the address space");
        for(const auto &old : sim.regions)
            if(r.base < old.base + old.size && old.base < r.base + r.size)
                throw runtime_error("Overlapping regions");
        sim.regions.push_back(r);
    }
    if(sim.regions.empty()) throw runtime_error("Empty region file");
}

// Applies the selected legal state to Spike itself.
u64 applyPolicy(processor_t &p, GeneratorSim &sim, const Snapshot &before,
                const VInsn &insn, bool ones, bool segNone, bool spurious) {
    auto state = p.get_state();
    bool partial = state->trap_happened && (state->trap_code == 3 || state->trap_code == 4 ||
                                          state->trap_code == 5 || state->trap_code == 13);
    if(!insn.vector || (state->trap_happened && !(insn.load && partial))) {
        // Trapping segment stores: no VRF writes, memory still rolled back.
        if(!(segNone && insn.store && insn.nf > 1 && state->trap_happened)) return 0;
    }
    u64 k = p.VU.vstart->read();
    u64 edits = 0;
    vector<VSlot> slots;
    if(!state->trap_happened || (insn.load && partial))
        vbuildSlots(insn, before.pre, {state->trap_happened, k, p.VU.vl->read()}, slots);
    auto rf = static_cast<u8*>(p.VU.reg_file);
    for(const auto &s : slots) {
        bool fill = ones && ((s.cls == VClass::Tail && before.pre.vta) ||
                             (s.cls == VClass::Inactive && before.pre.vma) ||
                             s.cls == VClass::MaskTail || s.cls == VClass::MaskLdTail);
        u64 value = vslotGet(rf, s);
        if(fill) value = vslotOnes(s);
        if(segNone && s.cls == VClass::SegPartial) value = vslotGet(before.vrf.data(), s);
        if(spurious && s.cls == VClass::FfSpurious) value = 0x5a5aa5a5ull & vslotOnes(s);
        if(value != vslotGet(rf, s)) { ++edits; vslotSet(rf, s, value); }
    }
    if(segNone && state->trap_happened && insn.isVectorMem() && insn.nf > 1) {
        // IO side effects cannot be undone: "none" is for RAM only.
        for(const auto &a : sim.accesses)
            if(a.element == k && a.io) throw runtime_error("--seg-partial none cannot undo a partial IO segment");
        for(auto it = sim.accesses.rbegin(); it != sim.accesses.rend(); ++it)
            if(it->element == k && it->store) sim.memory.write(it->addr, it->old.size(), it->old.data());
        sim.accesses.erase(remove_if(sim.accesses.begin(), sim.accesses.end(),
                           [&](const Access &a) { return a.element == k; }), sim.accesses.end());
    }
    return edits;
}

struct Transport { bool store; u64 addr; vector<u8> data, enable; };
void emitMemory(ostream &out, GeneratorSim &sim, const VInsn &insn, unsigned beat) {
    vector<Transport> ram;
    map<pair<bool, u64>, size_t> beats;
    for(const auto &a : sim.accesses) {
        if(a.io) {
            out << format("rv io 0 {} {:x} {} {:x} {} 0\n", unsigned(a.store), a.addr,
                          hexBytes(a.data.data(), a.data.size()), (1ull << a.data.size()) - 1, a.data.size());
        } else if(!beat || !insn.isVectorMem()) {
            ram.push_back({a.store, a.addr, a.data, vector<u8>(a.data.size(), 1)});
        } else {
            for(size_t b = 0; b < a.data.size(); ++b) {
                u64 addr = a.addr + b, base = addr & ~u64(beat - 1);
                auto key = make_pair(a.store, base);
                auto it = beats.find(key);
                if(it == beats.end()) {
                    auto r = sim.region(base, beat);
                    // Region boundary: byte accesses for this beat.
                    if(!r || r->io) { ram.push_back({a.store, addr, {a.data[b]}, {1}}); continue; }
                    beats[key] = ram.size();
                    Transport t{a.store, base, vector<u8>(beat), vector<u8>(beat, a.store ? 0 : 1)};
                    sim.memory.read(base, beat, t.data.data());
                    ram.push_back(t);
                    it = beats.find(key);
                }
                auto &t = ram[it->second];
                t.data[addr - base] = a.data[b];
                t.enable[addr - base] = 1;
            }
        }
    }
    u64 loadId = 0, storeId = 0;
    for(const auto &a : ram) {
        u64 id = a.store ? storeId++ : loadId++;
        string kind = a.store ? "store" : "load";
        out << format("rv {} exe 0 {} {} {:x} {}", kind, id, a.data.size(), a.addr,
                      hexBytes(a.data.data(), a.data.size()));
        if(a.store) out << " " << byteMask(a.enable);
        out << format("\nrv {} com 0 {}\n", kind, id);
        // Broadcast early: records must survive until commit/trap.
        if(a.store) out << format("rv store bro 0 {}\n", id);
    }
}

void emitState(ostream &out, processor_t &p, const Snapshot &before, const VInsn &insn, unsigned beat) {
    auto s = p.get_state();
    Snapshot after(p);
    if(!s->trap_happened) {
        for(const auto &[key, value] : s->log_reg_write) {
            u32 kind = key & 15, reg = key >> 4;
            if(kind == 0 && reg != 0) out << format("rv rf w 0 0 {} {:016x}\n", reg, value.v[0]);
            if(kind == 1) out << format("rv rf w 0 1 {} {:016x}{:016x}\n", reg, value.v[1], value.v[0]);
        }
        if(insn.csr) {
            u32 funct3 = (insn.bits >> 12) & 7;
            // CSR reads are checked through rd.
            if(insn.vd != 0)
                out << format("rv rf r 0 4 {} {:016x}\n", insn.csrAddr, s->XPR[insn.vd]);
            if(insn.csrWrites) {
                u64 value = s->csrmap.at(insn.csrAddr)->read();
                if(isVectorCsrAddr(insn.csrAddr)) value = after.csrs.at(insn.csrAddr);
                out << format("rv rf w 0 4 {} {:016x}\n", insn.csrAddr, value);
            }
        }
    }
    for(u32 a : {CSR_VL, CSR_VTYPE, CSR_VSTART, CSR_VXSAT, CSR_VXRM}) {
        // Explicit CSR writes get no extra implicit event.
        if(insn.csr && insn.csrWrites && !s->trap_happened &&
           (insn.csrAddr == a || (insn.csrAddr == CSR_VCSR && (a == CSR_VXRM || a == CSR_VXSAT)))) continue;
        if(before.csrs.at(a) != after.csrs.at(a))
            out << format("rv rf w 0 5 {} {:016x}\n", a, after.csrs.at(a));
    }
    if(before.vs != after.vs) out << format("rv vs 0 {}\n", after.vs);
    unsigned bytes = p.VU.VLEN / 8;
    unsigned chunk = beat ? min(beat, bytes) : bytes;
    for(unsigned reg = 0; reg < 32; ++reg) {
        for(unsigned start = 0; start < bytes; start += chunk) {
            vector<u8> enable(bytes, 0);
            bool changed = false;
            for(unsigned b = start; b < min(start + chunk, bytes); ++b)
                changed |= (enable[b] = before.vrf[reg * bytes + b] != after.vrf[reg * bytes + b]);
            if(changed) out << format("rv vrf w 0 {} {} {}\n", reg, byteMask(enable),
                                     hexBytes(after.vrf.data() + reg * bytes, bytes));
        }
    }
}

int generate(int argc, char **argv) {
    string elfPath, regionPath, output, isa, priv = "MSU", reset = "0x80000000";
    string policy = "spike", segPolicy = "spike";
    vector<string> trimRules;
    unsigned beat = 0;
    u64 maxInstructions = 200000;
    bool spurious = false, ioWide = false;
    CLI::App app{"Generate DUT-format ASCII traces using an independent pinned Spike (RV32/RV64, Zve32x/Zve64x)"};
    app.add_option("--elf", elfPath)->required();
    app.add_option("--regions", regionPath)->required();
    app.add_option("--output,-o", output)->required();
    app.add_option("--isa", isa)->required();
    app.add_option("--priv", priv)->default_val(priv);
    app.add_option("--reset-pc", reset)->default_val(reset);
    app.add_option("--max-instructions", maxInstructions)->default_val(maxInstructions);
    app.add_option("--beat-bytes", beat, "0: element accesses; 1/2/4/8/16/32/64: RAM beats and VRF chunks");
    app.add_option("--policy", policy, "spike or agnostic-ones")->check(CLI::IsMember({"spike", "agnostic-ones"}));
    app.add_option("--ff-trim", trimRules, "Repeatable SYMBOL:N; trim a labelled fault-only-first instruction before element N");
    app.add_flag("--ff-spurious", spurious, "Write a legal non-memory pattern into active trimmed-away FF elements");
    app.add_flag("--io-wide-fault", ioWide, "RV32: vector IO elements wider than 4 bytes take an access fault");
    app.add_option("--seg-partial", segPolicy, "spike or none (RAM only)")->check(CLI::IsMember({"spike", "none"}));
    CLI11_PARSE(app, argc, argv);
    if(beat > 64 || (beat && (beat & (beat - 1)))) throw runtime_error("Invalid beat size");
    if(!maxInstructions) throw runtime_error("Instruction limit must be positive");
    if(spurious && trimRules.empty()) throw runtime_error("--ff-spurious requires --ff-trim");
    if(priv != "MSU") throw runtime_error("tracegen: requires --priv MSU");
    u64 resetPc = number(reset);
    elfPath = filesystem::absolute(elfPath).string();
    if(elfPath.find_first_of(" \t\r\n") != string::npos)
        throw runtime_error("ASCII elf load paths cannot contain whitespace");
    if(!filesystem::is_regular_file(elfPath)) throw runtime_error("ELF does not exist: " + elfPath);
    Elf elf(elfPath.c_str());
    if(elf.reader.get_machine() != EM_RISCV || elf.reader.get_encoding() != ELFDATA2LSB)
        throw runtime_error("Expected a little-endian RISC-V ELF");
    unsigned xlen = elf.reader.get_class() == ELFCLASS64 ? 64 : 32;
    u64 xmask = xlen == 32 ? 0xffffffffull : ~0ull;
    if(resetPc > xmask || resetPc & 1) throw runtime_error("Invalid reset PC");
    if(ioWide && xlen != 32) throw runtime_error("--io-wide-fault requires RV32");
    GeneratorSim sim;
    sim.ioWide = ioWide;
    readRegions(regionPath, sim, xmask);
    auto symbols = readSymbols(elf, sim);
    if(!symbols.count("pass") || !symbols.count("fail")) throw runtime_error("ELF needs pass and fail symbols");
    map<u64, u64> trims;
    for(const auto &rule : trimRules) {
        auto pos = rule.find(':');
        if(pos == string::npos) throw runtime_error("--ff-trim expects SYMBOL:N");
        auto sym = symbols.find(rule.substr(0, pos));
        if(sym == symbols.end()) throw runtime_error("Unknown FF symbol: " + rule.substr(0, pos));
        if(!trims.emplace(sym->second, number(rule.substr(pos + 1))).second) throw runtime_error("Duplicate FF rule");
    }
    set<u64> usedTrims;
    elf.visitBytes([&](u8 byte, u64 addr) {
        auto r = sim.region(addr, 1);
        if(!r || r->io) throw runtime_error("ELF allocation outside RAM");
        sim.memory.write(addr, 1, &byte);
    });
    sim.cfg.isa = isa.c_str(); sim.cfg.priv = priv.c_str();
    sim.cfg.pmpregions = 0; sim.cfg.pmpgranularity = 4096; sim.cfg.trigger_count = 0;
    sim.cfg.hartids = {0}; sim.cfg.explicit_hartids = true;
    ofstream sink("/dev/null");
    auto closeLog = [](FILE *f) { fclose(f); };
    unique_ptr<FILE, decltype(closeLog)> logs(tmpfile(), closeLog);
    if(!logs) throw runtime_error("Cannot create Spike log file");
    processor_t proc(isa.c_str(), priv.c_str(), &sim.cfg, &sim, 0, false, logs.get(), sink);
    sim.proc = &proc; sim.harts[0] = &proc;
    proc.reset(); proc.enable_commit_log_state(); proc.paddr_bits_sim = 32;
    if(proc.get_xlen() != xlen || !proc.any_vector_extensions() || (proc.VU.ELEN != 32 && proc.VU.ELEN != 64) ||
       proc.VU.VLEN > 512) throw runtime_error("Expected the ELF's XLEN, ELEN 32 or 64 and VLEN<=512 from the ISA string");
    auto state = proc.get_state();
    state->pc = resetPc;
    // Same counter-enable reset as Hart.
    state->csrmap.at(CSR_MCOUNTEREN)->unlogged_backdoor_write(MCOUNTEREN_TIME);
    isa_parser_t parser(isa.c_str(), priv.c_str());
    disassembler_t disasm(&parser);
    string temporary = output + ".partial";
    ofstream out(temporary);
    if(!out) throw runtime_error("Cannot write " + temporary);
    out << "# RVLS vector trace v1; generated from Spike; no integrated vector RTL\n";
    out << format("memview new 0 4096 4096\nrv new 0 {} {} 32 0 0 0 0\n", isa, priv);
    VecPolicy accept;
    accept.agnostic = policy == "agnostic-ones";
    accept.ffTrimAny = !trims.empty(); accept.segPartialNone = segPolicy == "none";
    accept.ioWideFault = ioWide;
    out << "rv policy 0 " << accept.describe() << "\n";
    for(const auto &r : sim.regions) out << format("rv region add 0 {} {:x} {:x}\n", r.io ? 1 : 0, r.base, r.size);
    out << "elf load 0 " << elfPath << "\nrv set pc 0 " << format("{:x}", resetPc) << "\n";
    u64 count = 0, traps = 0, edits = 0;
    while(count < maxInstructions) {
        u64 pc = state->pc & xmask;
        if(pc == symbols.at("fail")) throw runtime_error(format("Program reached fail, gp={} pc=0x{:x}", state->XPR[3], pc));
        if(pc == symbols.at("pass")) break;
        Snapshot before(proc);
        sim.accesses.clear(); sim.trim.reset();
        // Fetch without stepping to pick the policy at this symbol.
        auto fetched = proc.get_mmu()->load_insn(pc);
        string text = disasm.disassemble(fetched.insn);
        VInsn insn = vdecode(u32(fetched.insn.bits()), text);
        sim.current = insn; sim.base = state->XPR[insn.rs1] & xmask;
        before.pre.xrs1 = state->XPR[insn.rs1];
        auto trim = trims.find(pc);
        if(trim != trims.end()) {
            if(!insn.ff || before.pre.vstart || trim->second < 1 || trim->second > before.pre.vl)
                throw runtime_error("FF trim requires a fault-only-first load, vstart=0 and 1<=N<=vl");
            sim.trim = trim->second; usedTrims.insert(pc);
        }
        out << format("# insn {} pc={:x} {}\n", count, pc, text);
        if(const char *symbol = sim.get_symbol(pc)) out << "# symbol " << symbol << "\n";
        state->last_inst = insn_t(0);
        proc.step(1);
        if(state->last_inst.bits() != fetched.insn.bits()) throw runtime_error("Spike did not execute the fetched instruction");
        if(state->trap_happened && state->trap_interrupt) throw runtime_error("tracegen: unexpected interrupt");
        edits += applyPolicy(proc, sim, before, insn, accept.agnostic, accept.segPartialNone, spurious);
        emitMemory(out, sim, insn, beat);
        emitState(out, proc, before, insn, beat);
        if(state->trap_happened) {
            ++traps;
            bool m = state->prv == PRV_M;
            out << format("rv trap 0 0 {} {:x} {:x}\n", state->trap_code,
                          (m ? state->mepc : state->sepc)->read() & xmask,
                          (m ? state->mtval : state->stval)->read() & xmask);
        } else out << format("rv commit 0 {:x}\n", pc);
        ++count;
    }
    if((state->pc & xmask) != symbols.at("pass")) throw runtime_error("Instruction limit reached before pass");
    if(usedTrims.size() != trims.size()) throw runtime_error("An FF trim rule was never executed");
    string io = ioWide ? format(" io-injections={}", sim.ioInjected) : "";
    out << format("# PASS instructions={} traps={} legal-element-edits={} ff-injections={}{}\n", count, traps, edits, sim.injected, io);
    out.flush();
    if(!out) throw runtime_error("Failed writing trace");
    out.close();
    filesystem::rename(temporary, output);
    cout << format("PASS {}: instructions={} traps={} legal-element-edits={} ff-injections={}{}\n", output, count, traps, edits, sim.injected, io);
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    try { return generate(argc, argv); }
    catch(const exception &e) { cerr << "tracegen: " << e.what() << '\n'; return 1; }
}
