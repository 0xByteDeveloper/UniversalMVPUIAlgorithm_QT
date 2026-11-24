// UMVPQT GOD STATE — Process / Memory Access Layer
// ============================================================================
//  IProcessReader: hedef surece harici (external) erisim soyutlamasi.
//  Linux : /proc/pid/maps + process_vm_readv  (sandbox testleri)
//  Win   : Toolhelp32 + ReadProcessMemory     (hedef platform)
//  32/64-bit hedef destekli (okunan adresler her zaman uint64'te).
// ============================================================================
#pragma once
#include "types.h"
#include <memory>
#include <string>
#include <vector>

namespace umvpqt {

struct ProcEntry {
    uint64_t    pid = 0;
    std::string name;
};

class IProcessReader {
public:
    virtual ~IProcessReader() = default;
    virtual bool open(uint64_t pid) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;
    virtual uint64_t pid() const = 0;
    virtual std::string name() const = 0;

    // Bellek erisimi
    virtual bool read(Addr addr, void* buf, size_t len) = 0;
    virtual bool readPtrSize(Addr addr, uint64_t& out) = 0;   // hedef ptr genisligi (4/8)
    virtual std::vector<MemRegion> regions() = 0;              // snapshot

    // 32-bit hedef mi?
    virtual bool targetIs64() const = 0;
    virtual int  ptrSize() const = 0;                          // 4 veya 8
    virtual Addr ptrMask() const = 0;                          // 0xFFFFFFFF veya tam

    // yardimcilar (template olamaz — inline inline impl)
    template <class T>
    bool readT(Addr addr, T& out) { return read(addr, &out, sizeof(T)); }

    uint8_t  readU8 (Addr a) { uint8_t  v{}; read(a, &v, 1); return v; }
    uint16_t readU16(Addr a) { uint16_t v{}; read(a, &v, 2); return v; }
    uint32_t readU32(Addr a) { uint32_t v{}; read(a, &v, 4); return v; }
    uint64_t readU64(Addr a) { uint64_t v{}; read(a, &v, 8); return v; }
    int32_t  readI32(Addr a) { int32_t  v{}; read(a, &v, 4); return v; }
    Addr     readAddr(Addr a) {          // hedef ptr genisliginde isaretci oku
        if (ptrSize() == 4) { uint32_t v{}; if (read(a, &v, 4)) return v; return 0; }
        uint64_t v{}; if (read(a, &v, 8)) return v; return 0;
    }
};

std::vector<ProcEntry> listProcesses();
std::unique_ptr<IProcessReader> openProcess(uint64_t pid);
std::unique_ptr<IProcessReader> openProcessByName(const std::string& name);

} // namespace umvpqt
