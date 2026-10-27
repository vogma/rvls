/*
 * Vector instruction decode and destination-element classification,
 * shared by the vector checker and apps/tracegen.
 */

#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include "type.h"

// Implementation-defined choices the checker accepts. Defaults match Spike.
struct VecPolicy {
    // Agnostic elements may keep their value or be all ones; mask tails may also
    // hold the vl=VLMAX result (norm:vreg_agnostic_op, norm:vreg_mask_tail_op).
    bool agnostic = false;
    // Fault-only-first may trim vl without a fault (norm:vector_ff_no_exception)
    // and update active elements in [new vl, old vl) (norm:vector_ff_past_trap).
    bool ffTrimAny = false;
    // Loads may overwrite active elements past the trapping element
    // (norm:vector_ls_overwrite_past_trap).
    bool loadPastTrapAny = false;
    // Faulting segment (norm:vector_ls_seg_partial_access): false = the fields
    // before the faulting field are accessed, as Spike does; true = none.
    bool segPartialNone = false;
    // RV32: an IO element wider than 4 bytes may take an access fault instead
    // of its access (norm:pma_io_rwx_per_sz); a fault-only-first load trims there.
    bool ioWideFault = false;
    // Validate-then-sync.  Disabled only for control runs, which must fail.
    bool sync = true;

    // key=value, keys as the field names; throws on an unknown key.
    void set(const std::string &key, const std::string &value);
    std::string describe() const;
};

// Decoded instruction, as far as the checker needs it.
struct VInsn {
    u32 bits = 0;
    std::string name;          // mnemonic (first token of the disassembly)
    bool vector = false;       // OP-V (not vset*) or a vector load/store
    bool vset = false;
    bool load = false, store = false;
    // SYSTEM CSR instruction (csrr*/csrr*i)
    bool csr = false, csrWrites = false;
    u32 csrAddr = 0;
    // memory
    u32 mop = 0, eewEnc = 0, nf = 1, lumop = 0;
    bool ff = false, whole = false, maskLdSt = false, indexed = false;
    bool vm = true;
    u32 vd = 0, rs1 = 0, rs2 = 0;
    // destination shape
    enum Kind { NONE, NORMAL, MASK, ELEM0, WHOLE, COMPRESS, MASKLD } kind = NONE;
    u32 eewMul = 1;            // NORMAL/ELEM0: destination EEW = SEW * eewMul
    bool allActive = false;    // v0 is a carry/select operand, not a mask
    bool maskAltVlen = false;  // mask-logical and vmsbf/vmsif/vmsof
    bool slideupX = false, slideupI = false;
    u32 wholeRegs = 0;         // WHOLE: number of registers

    bool isVectorMem() const { return load || store; }
};

// Vector state before the instruction.
struct VPre {
    u32 vlen = 0;              // bits
    u64 vl = 0, vstart = 0, vlmax = 0;
    u32 sew = 8;
    double lmul = 1;
    bool vta = false, vma = false, vill = true;
    const u8 *vrf = nullptr;   // 32 * vlen/8 bytes
    u64 xrs1 = 0;              // x[rs1] before the instruction
};

enum class VClass : u8 {
    Prestart,   // index < vstart
    Unchanged,  // vslideup: index < OFFSET
    NoBody,     // vstart >= vl: nothing may change (norm:vstart_vl_dep)
    Active,     // body, active
    Inactive,   // body, masked off
    Tail,       // tail, vta governs
    MaskTail,   // tail of a mask destination: always agnostic
    MaskLdTail, // tail of vlm.v: always agnostic, no computed alternative
    Faulting,   // the element at which a load trapped (nf = 1)
    PastTrap,   // active element past a load trap
    SegPartial, // fields of the faulting segment
    FfSpurious, // active element in [new vl, old vl) of a trimmed ff load
};

const char *vclassName(VClass c);

struct VSlot {
    u32 bit;          // first bit in the VRF image (vreg * VLEN + offset)
    u32 bits;         // element width in bits (1 for mask bits)
    u64 index;        // element (or segment) index; bit index for MASK
    u32 field;        // segment field
    VClass cls;
};

// How the instruction ended, as seen after the step (post state).
struct VOutcome {
    bool trap = false;      // synchronous trap of this instruction
    u64 trapVstart = 0;     // vstart after the trap
    u64 postVl = 0;         // vl after the instruction (fault-only-first)
};

VInsn vdecode(u32 bits, const std::string &mnemonic);

bool isVectorCsrAddr(u32 address);

// Destination element classes of `insn`, given the pre state and the outcome.
// Every bit of the VRF not covered by a slot must not change.
void vbuildSlots(const VInsn &insn, const VPre &pre, const VOutcome &out, std::vector<VSlot> &slots);

// Element value helpers on a VRF image.
u64 vslotGet(const u8 *vrf, const VSlot &s);
void vslotSet(u8 *vrf, const VSlot &s, u64 value);
inline u64 vslotOnes(const VSlot &s) { return s.bits >= 64 ? ~0ull : ((1ull << s.bits) - 1); }
inline bool vmaskBit(const u8 *vrf, u64 bit) { return (vrf[bit / 8] >> (bit % 8)) & 1; }
