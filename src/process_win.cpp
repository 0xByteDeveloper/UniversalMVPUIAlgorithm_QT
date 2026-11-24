// =============================================================================
// UMVP-QT // src/process_win.cpp — Windows reader:
// Toolhelp32 process list, OpenProcess + ReadProcessMemory, module list via
// EnumProcessModules, PE export table resolution from target memory
// (QMetaObject::activate, QAbstractButton::click ... mangled or demangled
// patterns, MSVC and MinGW mangling both handled).
// =============================================================================
#ifdef _WIN32

#include "umvpqt/process.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstring>

namespace umvpqt {

namespace {

class WinProcessReader : public IProcessReader {
public:
    ~WinProcessReader() override {
        if (h_) CloseHandle(h_);
    }

    bool open(uint32_t pid) {
        h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                         PROCESS_CREATE_THREAD, FALSE, pid);
        if (!h_)
            h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h_) return false;
        pid_ = pid;
        char nm[MAX_PATH] = {0};
        HMODULE mods[1024];
        DWORD cb = 0;
        if (EnumProcessModules(h_, mods, sizeof mods, &cb) && cb > 0) {
            for (DWORD i = 0; i < cb / sizeof(HMODULE) && i < 1024; ++i) {
                GetModuleFileNameExA(h_, mods[i], nm, MAX_PATH);
                std::string full(nm);
                size_t slash = full.rfind('\\');
                std::string base = slash == std::string::npos ? full : full.substr(slash + 1);
                MODULEINFO mi = {};
                GetModuleInformation(h_, mods[i], &mi, sizeof mi);
                MemoryRegion reg;
                reg.start = (Address)mods[i];
                reg.end = reg.start + mi.SizeOfImage;
                reg.perms = 5;             // mapped image: R+X (conservative)
                reg.name = base;
                reg.moduleBase = reg.start;
                regions_.push_back(reg);
                ModuleInfo m;
                m.name = base;
                m.base = reg.start;
                m.size = mi.SizeOfImage;
                std::string low = base;
                for (char& c : low) c = (char)tolower((unsigned char)c);
                if (low.find("qt6core") != std::string::npos) { m.isQtCore = true; m.qtFlavor = "qt6"; }
                if (low.find("qt5core") != std::string::npos ||
                    low.find("libqtcore") != std::string::npos) { m.isQtCore = true; m.qtFlavor = "qt5"; }
                modules_.push_back(m);
                // rw data sections of modules: add .data/.rdata region approximations
                // (heap scanning uses VirtualQueryEx below)
            }
        }
        refresh_heap_regions();
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        info_.pid = pid;
        info_.arch = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL
                         ? Arch::X86 : Arch::X64;
        info_.name = process_name(pid);
        return true;
    }

    void refresh_heap_regions() {
        // enumerate committed RW regions (heap + data)
        Address addr = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQueryEx(h_, (LPCVOID)addr, &mbi, sizeof mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                MemoryRegion reg;
                reg.start = (Address)mbi.BaseAddress;
                reg.end = reg.start + mbi.RegionSize;
                reg.perms = 2 | 1 | (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ) ? 4 : 0);
                regions_.push_back(reg);
            }
            addr = (Address)mbi.BaseAddress + mbi.RegionSize;
            if (addr < (Address)mbi.BaseAddress) break;
        }
    }

    static std::string process_name(uint32_t pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return "pid_" + std::to_string(pid);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof pe;
        std::string name;
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { name = pe.szExeFile; break; }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        return name.empty() ? "pid_" + std::to_string(pid) : name;
    }

    bool read(Address addr, void* buf, size_t len) override {
        SIZE_T got = 0;
        if (!ReadProcessMemory(h_, (LPCVOID)addr, buf, len, &got)) return false;
        return got == len;
    }
    const std::vector<MemoryRegion>& regions() override { return regions_; }
    const std::vector<ModuleInfo>& modules() override { return modules_; }
    ProcessInfo info() const override { return info_; }
    void* native() const override { return h_; }

private:
    HANDLE h_ = nullptr;
    uint32_t pid_ = 0;
    ProcessInfo info_;
    std::vector<MemoryRegion> regions_;
    std::vector<ModuleInfo> modules_;
};

} // namespace

std::vector<ProcessInfo> list_processes() {
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;
    if (Process32First(snap, &pe)) {
        do {
            ProcessInfo p;
            p.pid = pe.th32ProcessID;
            p.name = pe.szExeFile;
            p.arch = Arch::X64;   // refined on open
            out.push_back(p);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::unique_ptr<IProcessReader> open_process_by_pid(uint32_t pid) {
    auto r = std::make_unique<WinProcessReader>();
    if (!r->open(pid)) return nullptr;
    return r;
}

std::unique_ptr<IProcessReader> open_process_by_name(const std::string& name) {
    for (const ProcessInfo& p : list_processes()) {
        if (p.name == name || p.name.find(name) != std::string::npos)
            if (auto r = open_process_by_pid(p.pid)) return r;
    }
    return nullptr;
}

// ---- PE export resolution ------------------------------------------------------
std::vector<ExportEntry> list_exports(IProcessReader& r, const ModuleInfo& mod) {
    std::vector<ExportEntry> out;
    uint8_t dos[0x40] = {0};
    if (!r.read(mod.base, dos, sizeof dos)) return out;
    if (dos[0] != 'M' || dos[1] != 'Z') return out;
    uint32_t peOff = 0;
    r.readU32(mod.base + 0x3C, &peOff);
    Address pe = mod.base + peOff;
    uint8_t sig[4] = {0};
    if (!r.read(pe, sig, 4) || memcmp(sig, "PE\0\0", 4)) return out;
    uint16_t machine = 0, nsects = 0, optSize = 0;
    r.readU16(pe + 4, &machine);
    r.readU16(pe + 6, &nsects);
    r.readU16(pe + 20, &optSize);
    Address opt = pe + 24;
    uint16_t magic = 0;
    r.readU16(opt, &magic);
    if (magic != 0x20B && magic != 0x10B) return out;
    uint32_t expRva = 0;
    r.readU32(opt + (magic == 0x20B ? 112 : 96), &expRva);
    if (!expRva) return out;
    // sections for RVA->VA
    Address secTable = opt + optSize;
    struct Sec { uint32_t va, vsz, rawsz; };
    std::vector<Sec> secs;
    for (int i = 0; i < nsects && i < 96; ++i) {
        Sec s = {};
        // PE section header (40B): +0 name, +8 VirtualSize, +12 VirtualAddress,
        // +16 SizeOfRawData
        r.readU32(secTable + (Address)i * 40 + 8, &s.vsz);
        r.readU32(secTable + (Address)i * 40 + 12, &s.va);
        r.readU32(secTable + (Address)i * 40 + 16, &s.rawsz);
        secs.push_back(s);
    }
    auto rva2va = [&](uint32_t rva) -> Address {
        for (const Sec& s : secs)
            if (rva >= s.va && rva < s.va + std::max(s.vsz, s.rawsz))
                return mod.base + s.va + (rva - s.va);
        if (!secs.empty() && rva < secs[0].va) return mod.base + rva;   // headers
        return 0;
    };
    Address exp = rva2va(expRva);
    if (!exp) return out;
    uint32_t nNames = 0;
    r.readU32(exp + 24, &nNames);
    uint32_t addrNames = 0, addrFn = 0, addrOrd = 0;
    r.readU32(exp + 32, &addrNames);
    r.readU32(exp + 28, &addrFn);
    r.readU32(exp + 36, &addrOrd);
    if (nNames > 100000) nNames = 100000;
    for (uint32_t i = 0; i < nNames; ++i) {
        uint32_t nameRva = 0;
        if (!r.readU32(rva2va(addrNames) + (Address)i * 4, &nameRva)) break;
        Address na = rva2va(nameRva);
        if (!na) continue;
        std::string nm;
        char c = 0;
        for (int k = 0; k < 1024 && r.read(na + (Address)k, &c, 1) && c; ++k) nm += c;
        ExportEntry e;
        e.name = nm;
        uint16_t ord = 0;
        r.readU16(rva2va(addrOrd) + (Address)i * 2, &ord);
        uint32_t fnRva = 0;
        r.readU32(rva2va(addrFn) + (Address)ord * 4, &fnRva);
        e.address = rva2va(fnRva);
        out.push_back(e);
    }
    return out;
}

Address resolve_export(IProcessReader& r, const ModuleInfo& mod,
                       const std::string& pattern) {
    for (const ExportEntry& e : list_exports(r, mod))
        if (e.name.find(pattern) != std::string::npos) return e.address;
    return 0;
}

} // namespace umvpqt

#endif // _WIN32
