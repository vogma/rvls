#pragma once
#include <sys/syscall.h>
#include "stddef.h"
#include "type.h"
#include "memory.hpp"
#include <vector>
#include <map>
#include <list>
#include <memory>

using namespace std;

class Context;

class MemoryView{
public:

};

class DirectMemoryView : public MemoryView{
public:

};

// Memory model of one CPU, built from its load/store events.
// Records are copied at `exe` and live until their instruction is checked.
// Re-executing an uncommitted id replaces it; reusing a committed one fails.
class CpuMemoryView : public MemoryView{
public:
    static constexpr size_t MAX_ACCESS_BYTES = 64;

    CpuMemoryView(Context& context, Memory &memory, u64 readIds, u64 writeIds);
    void bindHartId(u32 hartId);
    CpuMemoryView(const CpuMemoryView&) = delete;
    CpuMemoryView(CpuMemoryView&&) = delete;
    u32 hartId = u32(-1);

    class Access{
    public:
        u64 id = 0, gen = 0;
        u64 addr = 0;
        size_t len = 0;
        u8 bytes[MAX_ACCESS_BYTES];
        u8 enable[MAX_ACCESS_BYTES]; // byte enables (stores); loads enable every byte
        u64 epoch = 0;
        bool isStore = false;
        bool executed = false, commited = false, broadcasted = false, consumed = false, linked = false;
        bool used = false; // touched by a Spike access of its instruction (vector loads)

        bool covers(u64 a) const { return a >= addr && a < addr + len && enable[a - addr]; }

        inline void bypass(Access &load) const {
            if(load.addr < this->addr + this->len &&
               this->addr < load.addr + load.len){
                u64 startAt = max(load.addr, this->addr);
                u64 endAt = min(load.addr + load.len, this->addr + this->len);
                for(u64 a = startAt; a < endAt; a++){
                    if(enable[a - this->addr]) load.bytes[a - load.addr] = this->bytes[a - this->addr];
                }
            }
        }
    };
    using AccessP = shared_ptr<Access>;

    // Live records by DUT id.
    map<u64, AccessP> liveLoads, liveStores;
    // Executed, not yet committed loads (they receive bypass from stores Spike checks).
    vector<AccessP> loadsInflight;
    // Committed, not yet broadcast stores, oldest first (bypass source for later loads).
    list<AccessP> storeBypass;
    // Accesses committed since the last commit/trap: owned by the next one.
    vector<AccessP> pendingLoads, pendingStores;
    size_t pendingLoadCursor = 0, pendingStoreCursor = 0;

    u64 readIds, writeIds;
    Context& context;
    Memory &memory;
    u64 epoch = 0;
    u64 genCounter = 0;

    //CPU interface
    void loadExecute(u64 id, u64 addr, size_t len, const u8* bytes);
    void loadCommit(u64 id);
    void loadFlush();
    void storeExecute(u64 id, u64 addr, size_t len, const u8* bytes, const u8* enable = nullptr);
    void storeCommit(u64 id);
    void storeBroadcast(u64 id);

    //Spike interface (one scalar access per instruction, in commit order)
    void fetch(u64 address,u32 length, u8 *data);
    void mmu(u64 address,u32 length, u8 *data);
    void load(u64 address,u32 length, u8 *data);
    void store(u64 address,u32 length, const u8 *data);
    // Ends a scalar instruction: every committed access must have been consumed.
    void step();

    // Vector loads: Spike element data from the newest covering DUT load.
    // Returns false if a byte is not covered.
    bool vectorLoad(u64 address, u32 length, u8 *data);
    // Reads memory as a new load would see it (memory + committed stores).
    void readWithBypass(u64 address, u32 length, u8 *data);
    // Applies one checked DUT store to the inflight loads, as store() does.
    void bypassInflight(const Access &store);
    // Ends a vector instruction: releases all its accesses.
    void releasePending();
    void reportIdReuse(const char *kind, u64 id);
};
