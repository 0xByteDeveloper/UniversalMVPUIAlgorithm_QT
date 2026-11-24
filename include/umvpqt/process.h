// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/process.h
// Process access: IProcessReader (RPM on Windows, /proc on Linux, Mock for
// tests) + region/module snapshot + PE export resolution (invoke god mode).
// =============================================================================
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "types.h"

namespace umvpqt {

struct MemoryRegion {
    Address start = 0, end = 0;
    uint32_t perms = 0;     // bit0 R, bit1 W, bit2 X
    std::string name;       // module name if mapped file, else ""
    Address moduleBase = 0; // 0 if anonymous heap/stack
};

struct ModuleInfo {
    std::string name;       // "Qt6Core.dll", "libQt5Core.so.5", "mock"
    Address base = 0, size = 0;
    bool isQtCore = false;
    std::string qtFlavor;   // "qt5"/"qt6"/""
};

// Abstraction over target memory — everything the scanner needs.
class IProcessReader {
public:
    virtual ~IProcessReader() = default;
    virtual bool read(Address addr, void* buf, size_t len) = 0;
    virtual const std::vector<MemoryRegion>& regions() = 0;
    virtual const std::vector<ModuleInfo>& modules() = 0;
    virtual ProcessInfo info() const = 0;
    // OS-native handle (HANDLE on Windows; fd on Linux) for remote execution.
    virtual void* native() const { return nullptr; }

    // typed helpers
    template <typename T>
    bool readT(Address addr, T* out) { return read(addr, out, sizeof(T)); }
    bool readU64(Address addr, uint64_t* out) { return read(addr, out, 8); }
    bool readU32(Address addr, uint32_t* out) { return read(addr, out, 4); }
    bool readU16(Address addr, uint16_t* out) { return read(addr, out, 2); }
    bool readI32(Address addr, int32_t* out) { return read(addr, out, 4); }
    Address readPtr(Address addr) {
        uint64_t v = 0;
        return readU64(addr, &v) ? (Address)v : 0;
    }

    bool isReadable(Address a) const;
    bool isWritable(Address a) const;
    bool isExecutable(Address a) const;
    bool inModule(Address a, const std::string& namePart) const;
};

// PE export resolution (Windows builds; mock fallback returns 0).
struct ExportEntry { std::string name; Address address; };
Address resolve_export(IProcessReader& r, const ModuleInfo& mod,
                       const std::string& mangledOrPattern);
std::vector<ExportEntry> list_exports(IProcessReader& r, const ModuleInfo& mod);

// Process listing (platform impl in process_posix.cpp / process_win.cpp).
std::vector<ProcessInfo> list_processes();

// Real reader implementations.
std::unique_ptr<IProcessReader> open_process_by_pid(uint32_t pid);
std::unique_ptr<IProcessReader> open_process_by_name(const std::string& name);

} // namespace umvpqt
