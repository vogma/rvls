#ifdef RVLS_JNI

#include <jni.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <queue>
#include <sstream>
#include <vector>
#include "context.hpp"
#include "config.hpp"
#include "hart.hpp"
#include "disasm.h"

class RvlsDisassembler {
public:
	isa_parser_t isa;
	disassembler_t disassembler;

	RvlsDisassembler(int xlen) :
		isa(xlen == 32 ? "rv32i" : "rv64i", "msu"),
		disassembler(&isa) {
	}
};

#ifdef __cplusplus
extern "C" {
#endif

jclass userDataClass;
jmethodID methodId;

#define rvlsJni(n) JNIEXPORT void JNICALL Java_rvls_jni_Frontend_##n(JNIEnv * env, jobject obj, long handle
#define rvlsJniBool(n) JNIEXPORT bool JNICALL Java_rvls_jni_Frontend_##n(JNIEnv * env, jobject obj, long handle
#define rvlsJniString(n) JNIEXPORT jstring JNICALL Java_rvls_jni_Frontend_##n(JNIEnv * env, jobject obj, long handle

#define c ((Context*)handle)
#define rv ({ \
	auto tmp = c->harts.find(hartId); \
	auto* hart = tmp != c->harts.end() ? (&tmp->second) : nullptr; \
	hart; \
})

static std::vector<u8> readJniBytes(JNIEnv *env, jbyteArray array, size_t expected){
    if(array == nullptr) throw std::runtime_error("Null RVLS data byte array");
    const jsize size = env->GetArrayLength(array);
    if(expected > CpuMemoryView::MAX_ACCESS_BYTES || size != static_cast<jsize>(expected)) throw std::runtime_error("Bad RVLS data byte array length");

    std::vector<u8> data(size);
    env->GetByteArrayRegion(array, 0, size, reinterpret_cast<jbyte *>(data.data()));
    return data;
}

// Packed byte-enable mask to one 0/1 entry per byte.
static std::vector<u8> readJniMask(JNIEnv *env, jbyteArray array, size_t size){
    if(array == nullptr) throw std::runtime_error("Null RVLS mask byte array");
    const jsize length = env->GetArrayLength(array);
    if(length != static_cast<jsize>((size + 7) / 8)) throw std::runtime_error("Bad RVLS mask byte array length");
    std::vector<u8> packed(length);
    env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte *>(packed.data()));
    std::vector<u8> enable(size);
    for(size_t i = 0; i < size_t(length) * 8; ++i){
        u8 bit = (packed[i / 8] >> (i % 8)) & 1;
        if(i < size) enable[i] = bit;
        else if(bit) throw std::runtime_error("RVLS mask enables a byte past the data");
    }
    return enable;
}

string toString(JNIEnv *env, jstring jstr){
    const char * chars;
    chars = env->GetStringUTFChars(jstr, NULL ) ;
    string str = string(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return str;
}

JNIEXPORT jlong JNICALL Java_rvls_jni_Frontend_newDisassemble(JNIEnv * env, jobject obj, int xlen){
    return  (jlong) new RvlsDisassembler(xlen);
}

JNIEXPORT jstring JNICALL Java_rvls_jni_Frontend_disassemble(JNIEnv * env, jobject obj, long handle, long instruction){
	std::string str = ((RvlsDisassembler*)handle)->disassembler.disassemble(instruction);
	jstring result = env->NewStringUTF(str.c_str());
    return result;
}

JNIEXPORT void JNICALL Java_rvls_jni_Frontend_deleteDisassemble(JNIEnv * env, jobject obj, long handle){
	delete (RvlsDisassembler*)handle;
}


JNIEXPORT jlong JNICALL Java_rvls_jni_Frontend_newContext(JNIEnv * env, jobject obj, jstring jworkspace){
	string workspace = toString(env, jworkspace);
	auto *ctx = new Context();
	ctx->spikeLogs = fopen((workspace + "/spike.log").c_str(), "w");
    return (jlong)ctx;
}

rvlsJni(deleteContext)){
    delete (Context*)handle;
}

rvlsJni(spikeDebug), jboolean enable){
    c->config.spikeDebug = enable;
	for(auto& [hartId, hart] : c->harts){
		hart.proc->debug = enable;
	}
}

rvlsJni(spikeLogCommit), jboolean enable){
	c->config.spikeLogCommit = enable;
	for(auto& [hartId, hart] : c->harts){
		if(enable)  hart.proc->enable_log_commits();
		if(!enable) {
			hart.proc->disable_log_commits();
			hart.proc->enable_commit_log_state();
		}
	}
}
rvlsJni(time), unsigned long value){
    c->time = value;
}


rvlsJni(newCpuMemoryView),int viewId, long readIds, long writeIds){
	c->cpuMemoryViewNew(viewId, readIds, writeIds);
}

rvlsJni(newCpu),int hartId, jstring isa, jstring priv, int physWidth, int pmpNum, int triggerCount, int asidWidth, int memoryViewId){
	c->rvNew(hartId, toString(env, isa), toString(env, priv), physWidth, pmpNum, triggerCount, asidWidth, memoryViewId, c->spikeLogs);
}

rvlsJni(loadElf), long offset, jstring path){
	c->loadElf(toString(env, path), offset);
}

rvlsJni(loadBin), long offset, jstring path){
	c->loadBin(toString(env, path), offset);
}

rvlsJni(loadBytes), long offset, jbyteArray array){
	jbyte* bufferPtr = env->GetByteArrayElements(array, NULL);
	jsize lengthOfArray = env->GetArrayLength(array);
	c->loadBytes(offset, lengthOfArray, (u8*)bufferPtr);
	env->ReleaseByteArrayElements(array, bufferPtr, 0);
}

rvlsJni(setPc), int hartId, long pc){
	rv->setPc(pc);
}
rvlsJni(setRegister), int hartId, int id, long value){
    try{
        rv->setRegister(id, value);
    } catch (const std::exception &e) {
        auto exception = env->FindClass("java/lang/IllegalArgumentException");
        if(exception != nullptr){
            env->ThrowNew(exception, e.what());
            env->DeleteLocalRef(exception);
        }
    }
}
rvlsJni(writeRf), int hartId, int rfKind, int address, jbyteArray data){
    try{
        auto bytes = readJniBytes(env, data, rfKind == 1 ? 16 : 8);
        rv->writeRf(rfKind, address, bytes);
    } catch (const std::exception &e) {
        c->lastErrorMessage = e.what();
        auto exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        if(exceptionClass != nullptr) env->ThrowNew(exceptionClass, e.what());
    }
}
rvlsJni(readRf), int hartId, int rfKind, int address, jbyteArray data) {
    try{
        auto bytes = readJniBytes(env, data, 8);
        rv->readRf(rfKind, address, bytes);
    } catch (const std::exception &e) {
        c->lastErrorMessage = e.what();
        auto exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        if(exceptionClass != nullptr) env->ThrowNew(exceptionClass, e.what());
    }
}

rvlsJniBool(commit), int hartId, long pc) {
	try{
		rv->commit(pc);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(trap), int hartId, jboolean interrupt, int code) {
	try{
		rv->trap(interrupt, code);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}

// Synchronous trap with xepc/xtval (required for vector instructions).
rvlsJniBool(trapWithFields), int hartId, jboolean interrupt, int code, long epc, long tval) {
	try{
		rv->trap(interrupt, code, true, epc, tval);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}

// Vector state events.
rvlsJniBool(writeVrf), int hartId, int vreg, jbyteArray mask, jbyteArray data) {
	try{
		if(data == nullptr) throw std::runtime_error("Null RVLS data byte array");
		auto bytes = readJniBytes(env, data, env->GetArrayLength(data));
		rv->writeVrf(vreg, readJniMask(env, mask, bytes.size()), bytes);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(writeVs), int hartId, int value) {
	try{
		rv->writeVs(value);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(setPolicy), int hartId, jstring policy) {
	try{
		rv->setPolicy(toString(env, policy));
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}

rvlsJniString(getLastErrorMessage)) {
	std::string str = c->lastErrorMessage;
	jstring result = env->NewStringUTF(str.c_str());
	return result;
}


rvlsJni(ioAccess), int hartId, jboolean write, long address, jbyteArray data, int mask, int size, jboolean error){
    try{
        TraceIo a;
        a.write = write;
        a.address = address;
        a.data = readJniBytes(env, data, size);
        a.mask = mask;
        a.size = size;
        a.error = error;
        rv->ioAccess(a);
    } catch (const std::exception &e) {
        c->lastErrorMessage = e.what();
        auto exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        if(exceptionClass != nullptr) env->ThrowNew(exceptionClass, e.what());
    }
}

rvlsJni(setInterrupt), int hartId, int intId, jboolean value){
    rv->setInt(intId, value);
}
rvlsJni(addRegion), int hartId, int kind, long base, long size){
	Region r;
	r.type = (RegionType)kind;
	r.base = base;
	r.size = size;
    rv->addRegion(r);
}
rvlsJniBool(loadExecute), int hartId, long id, long addr, long len, jbyteArray data){
	try{
		auto bytes = readJniBytes(env, data, len);
        rv->memory->loadExecute(id, addr, len, bytes.data());
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(loadCommit), int hartId, long id){
	try{
        rv->memory->loadCommit( id);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(loadFlush), int hartId){
	try{
        rv->memory->loadFlush();
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(storeExecute), int hartId, long id, long addr, long len, jbyteArray data){
	try{
		auto bytes = readJniBytes(env, data, len);
        rv->memory->storeExecute(id, addr, len, bytes.data());
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(storeExecuteMasked), int hartId, long id, long addr, long len, jbyteArray data, jbyteArray mask){
	try{
		auto bytes = readJniBytes(env, data, len);
		auto enable = readJniMask(env, mask, len);
        rv->memory->storeExecute(id, addr, len, bytes.data(), enable.data());
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(storeCommit), int hartId, long id){
	try{
        rv->memory->storeCommit(id);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(storeBroadcast), int hartId, long id){
	try{
        rv->memory->storeBroadcast(id);
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(finish)){
	try{
        c->finish();
	} catch (const std::exception &e) {
		c->lastErrorMessage = e.what();
	    return false;
	}
	return true;
}
rvlsJniBool(storeConditional), int hartId, jboolean failure){
    try{
        rv->scStatus(failure);
    } catch (const std::exception &e) {
        c->lastErrorMessage = e.what();
        return false;
    }
    return true;
}


#ifdef __cplusplus
}
#endif

#endif
