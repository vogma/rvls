/*
 * RVV state checking for RVLS.
 *
 * Steps Spike, compares its vector state with the DUT's, validates legal
 * differences against the policy, then syncs them into Spike.
 */

#pragma once

// Before <memory>: Spike's syscall.h shadows the system one.
#include <sys/syscall.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <span>
#include "type.h"
#include "processor.h"
#include "disasm.h"
#include "vshape.hpp"

class Hart;
class Context;

struct VecCsrs {
    u64 vl = 0, vtype = 0, vstart = 0, vxrm = 0, vxsat = 0, vs = 0;
};

class VectorChecker {
public:
    VectorChecker(Hart &hart);

    Hart &hart;
    processor_t *proc;
    state_t *state;
    u32 vlenb, vlen, xlen;
    VecPolicy policy;
    std::unique_ptr<isa_parser_t> isa;
    std::unique_ptr<disassembler_t> disasm;

    // DUT shadow of the vector state; the VRF starts at zero.
    std::vector<u8> dutVrf;
    VecCsrs dutCsr;

    // Events of the current instruction.
    std::vector<u8> evVrf, evWritten;
    std::map<u32, u64> evImplicit;
    bool evVs = false; u64 evVsValue = 0;
    bool evExplicit = false; u32 evExplicitAddr = 0; u64 evExplicitValue = 0;

    // DUT events
    void vrfWrite(u32 reg, std::span<const u8> enable, std::span<const u8> data);
    void implicitCsr(u32 address, u64 value);
    void vsWrite(u64 value);
    void explicitCsrWrite(u32 address, u64 value);
    void setPolicy(const std::string &keyValues);

    // Called by Hart around proc->step(1); cause is the DUT's synchronous trap cause, else -1.
    void beforeStep(bool trapStep, int cause = -1);
    void afterStep(bool trap, bool interrupt, u32 code);
    // After afterStep: the stepped instruction was a vector instruction.
    bool lastWasVector() const { return executed && (cur.vector || cur.vset); }
    // During a vector load/store step, Spike's memory callbacks come here.
    bool routesMemory();
    // Fault-only-first trimming and wide IO faults: true makes Spike take an access fault.
    bool injectsFault(u64 addr, u32 len, bool store);
    void spikeLoad(u64 addr, u32 len, u8 *bytes);
    void spikeStore(u64 addr, u32 len, const u8 *bytes);

    std::string formatContext() const;

private:
    // Pre-step state of the current instruction.
    std::vector<u8> preVrf;
    VecCsrs pre;
    VPre vpre;
    reg_t preXpr[32];
    u64 prePc = 0;
    bool stepActive = false, trapStep = false;
    int trapCause = -1;
    bool decoded = false, executed = false;
    VInsn cur;
    std::string curText;

    struct SpikeAccess { u64 addr; u32 len; std::vector<u8> data; u64 elem; };
    std::vector<SpikeAccess> spikeLoads, spikeStores;
    std::vector<SpikeAccess> loadMisses;
    u64 extraLoadBytes = 0;

    VecCsrs readSpikeCsrs() const;
    u64 trunc(u64 v) const { return xlen == 64 ? v : (v & 0xffffffffull); }
    void decodeCurrent();
    u64 currentElement(u64 addr) const;
    void resetEvents();
    bool computeAlt(bool vlenForm, std::vector<u8> &out);
    void checkExplicitCsr(bool trap);
    void checkCsrs(VecCsrs &post);
    void checkMemory(bool trap, const VecCsrs &post);
    void checkVrf(bool trap, u32 code, const VecCsrs &post);
    [[noreturn]] void fail(const std::string &cls, const std::string &detail) const;
    std::string slotName(const VSlot &s) const;
};
