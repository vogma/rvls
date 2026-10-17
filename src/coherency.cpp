#include "coherency.hpp"
#include <string.h>
#include <algorithm>
#include "global.hpp"
#include "context.hpp"

CpuMemoryView::CpuMemoryView(Context& context, Memory &memory, u64 readIds, u64 writeIds) : readIds(readIds), writeIds(writeIds), context(context), memory(memory){
}

void CpuMemoryView::bindHartId(u32 hartId){
    this->hartId = hartId;
}

void CpuMemoryView::reportIdReuse(const char *kind, u64 id){
    failure(context, hartId, "ACCESS ID REUSED: %s id %lu is still owned by an unchecked instruction\n", kind, id);
}


//Nax interface
void CpuMemoryView::loadExecute(u64 id, u64 addr, size_t len, const u8* bytes){
    if(len > MAX_ACCESS_BYTES) throw std::runtime_error("Load len to big ???");
    if(id >= readIds) throw std::runtime_error("Load id out of range ???");
    AccessP load;
    auto it = liveLoads.find(id);
    if(it != liveLoads.end()){
        if(it->second->commited) reportIdReuse("load", id);
        load = it->second; // replay of an uncommitted load
    } else {
        load = std::make_shared<Access>();
        load->id = id;
        load->gen = ++genCounter;
        liveLoads[id] = load;
        loadsInflight.push_back(load);
    }
    load->addr = addr;
    load->len = len;
    load->epoch = epoch++;
    load->executed = true;
    memset(load->enable, 1, len);
    memory.read(addr, len, load->bytes);
    for(auto &store : storeBypass){
        store->bypass(*load);
    }
}

void CpuMemoryView::loadCommit(u64 id){
    auto it = liveLoads.find(id);
    if(it == liveLoads.end() || !it->second->executed) throw std::runtime_error("Load was valid ???");
    auto load = it->second;
    if(load->commited) throw std::runtime_error("Load was already commited ???");
    load->commited = true;
    loadsInflight.erase(std::remove(loadsInflight.begin(), loadsInflight.end(), load), loadsInflight.end());
    pendingLoads.push_back(load);
}

void CpuMemoryView::loadFlush(){
    for(auto &load : loadsInflight){
        auto it = liveLoads.find(load->id);
        if(it != liveLoads.end() && it->second == load) liveLoads.erase(it);
    }
    loadsInflight.clear();
}

void CpuMemoryView::storeExecute(u64 id, u64 addr, size_t len, const u8* bytes, const u8* enable){
    if(len > MAX_ACCESS_BYTES) throw std::runtime_error("Store len to big ???");
    if(id >= writeIds) throw std::runtime_error("Store id out of range ???");
    AccessP store;
    auto it = liveStores.find(id);
    if(it != liveStores.end()){
        store = it->second;
        if(store->commited) reportIdReuse("store", id);
        if(store->broadcasted) throw std::runtime_error("Store was already broadcasted ???");
    } else {
        store = std::make_shared<Access>();
        store->id = id;
        store->gen = ++genCounter;
        store->isStore = true;
        liveStores[id] = store;
    }
    store->executed = true;
    store->addr = addr;
    store->len = len;
    memcpy(store->bytes, bytes, len);
    if(enable) memcpy(store->enable, enable, len); else memset(store->enable, 1, len);
}

void CpuMemoryView::storeCommit(u64 id){
    auto it = liveStores.find(id);
    if(it == liveStores.end() || !it->second->executed) throw std::runtime_error("Store wasn't executed ???");
    auto store = it->second;
    if(store->commited) throw std::runtime_error("Store was already commited ???");
    store->commited = true;
    pendingStores.push_back(store);
    if(!store->broadcasted){
        storeBypass.push_back(store);
        store->linked = true;
    }
}

void CpuMemoryView::storeBroadcast(u64 id){
    auto it = liveStores.find(id);
    if(it == liveStores.end() || !it->second->executed) throw std::runtime_error("Store wasn't executed ???");
    auto store = it->second;
    if(store->broadcasted) throw std::runtime_error("Store was already broadcasted ???");
    for(size_t i = 0; i < store->len; i++){
        if(store->enable[i]) memory.write(store->addr + i, 1, store->bytes + i);
    }
    store->epoch = epoch;
    store->broadcasted = true;
    if(store->linked){
        storeBypass.remove(store);
        store->linked = false;
    }
    // The record stays owned until its instruction is checked.
    if(store->consumed) liveStores.erase(it);
}


//Spike interface
void CpuMemoryView::load(u64 address,u32 length, u8 *data){
    if(pendingLoadCursor >= pendingLoads.size())
        throw std::runtime_error("loadFresh wasn't NULL on check ???");
    auto &load = *pendingLoads[pendingLoadCursor++];
    assertEq(context, hartId, "Bad load addr", load.addr, address);
    assertEq(context, hartId, "Bad load length", load.len, length);
    memcpy(data, load.bytes, load.len);
    load.used = true;
}

void CpuMemoryView::store(u64 address,u32 length, const u8 *data){
    if(pendingStoreCursor >= pendingStores.size()) throw std::runtime_error("storeFresh wasn't valid on check ???");
    auto &store = *pendingStores[pendingStoreCursor++];
    assertEq(context, hartId, "Bad store addr", store.addr, address);
    assertEq(context, hartId, "Bad store length", store.len, length);
    bool bad = false;
    for(u32 i = 0; i < length; ++i) bad |= !store.enable[i] || store.bytes[i] != data[i];
    if(bad) {
        printf("Got, expected:\n");
        for(u32 i = 0; i < length; ++i)
            printf("%02X ", store.bytes[i]);
        printf("\n");
        for(u32 i = 0; i < length; ++i)
            printf("%02X ", data[i]);
        printf("\n");
        throw std::runtime_error("store bad data ???");
    }
    store.used = true;
    bypassInflight(store);
}

void CpuMemoryView::bypassInflight(const Access &store){
    //Bypass store values to inflight loads
    for(auto &load : loadsInflight){
        if(!store.broadcasted || load->epoch < store.epoch)
            store.bypass(*load);
    }
}

void CpuMemoryView::fetch(u64 address,u32 length, u8 *data){
    memory.read(address, length, data);
}

void CpuMemoryView::mmu(u64 address,u32 length, u8 *data){
    memory.read(address, length, data);
}

void CpuMemoryView::step(){
    if(pendingLoadCursor < pendingLoads.size()) throw std::runtime_error("loadFresh unused ???");
    if(pendingStoreCursor < pendingStores.size()) throw std::runtime_error("storeFresh unused ???");
    releasePending();
}

void CpuMemoryView::releasePending(){
    for(auto &load : pendingLoads){
        load->consumed = true;
        auto it = liveLoads.find(load->id);
        if(it != liveLoads.end() && it->second == load) liveLoads.erase(it);
    }
    for(auto &store : pendingStores){
        store->consumed = true;
        if(store->broadcasted){
            auto it = liveStores.find(store->id);
            if(it != liveStores.end() && it->second == store) liveStores.erase(it);
        }
    }
    pendingLoads.clear();
    pendingStores.clear();
    pendingLoadCursor = 0;
    pendingStoreCursor = 0;
}

void CpuMemoryView::checkBroadcastsCommitted(const char *where){
    for(auto &[id, store] : liveStores){
        if(store->broadcasted && !store->commited)
            failure(context, hartId, "STORE BROADCAST WITHOUT COMMIT: store id %lu at 0x%lx (%zu bytes) was not committed %s\n",
                    id, store->addr, store->len, where);
    }
}

bool CpuMemoryView::vectorLoad(u64 address, u32 length, u8 *data){
    bool all = true;
    for(u32 i = 0; i < length; i++){
        u64 a = address + i;
        bool found = false;
        for(auto it = pendingLoads.rbegin(); it != pendingLoads.rend(); ++it){
            if((*it)->covers(a)){
                data[i] = (*it)->bytes[a - (*it)->addr];
                (*it)->used = true;
                found = true;
                break;
            }
        }
        if(!found){
            all = false;
            readWithBypass(a, 1, data + i);
        }
    }
    return all;
}

void CpuMemoryView::readWithBypass(u64 address, u32 length, u8 *data){
    Access tmp;
    tmp.addr = address;
    tmp.len = length;
    memory.read(address, length, tmp.bytes);
    for(auto &store : storeBypass) store->bypass(tmp);
    memcpy(data, tmp.bytes, length);
}
