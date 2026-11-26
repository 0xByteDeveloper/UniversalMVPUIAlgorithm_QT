// UMVPQT GOD STATE — Windows Process Layer (hedef platform)
// ============================================================================
//  Toolhelp32 + OpenProcess + ReadProcessMemory + VirtualQueryEx.
//  Module listesi: CreateToolhelp32Snapshot(TH32CS_SNAPMODULE).
//  PE export tablosu BELLEKTEN cozulur (loadPeExports) — MSVC sembolleri
//  (??_7QWidget@@6B@, ?staticMetaObject@... gibi) PDB'siz okunur.
// ============================================================================
#include "umvpqt/process.h"
#include "umvpqt/module.h"

#ifdef _WIN32

#include <cstdio>
#include <cstring>
#include <windows.h>
#include <tlhelp32.h>

namespace umvpqt {

class WindowsProcess : public IProcessReader {
public:
    ~WindowsProcess() override { close(); }

    bool open(uint64_t pid) override {
        h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                          FALSE, (DWORD)pid);
        if (!h_) h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
        if (!h_) return false;
        pid_ = pid;
        reloadRegions();
        detectArch();
        return true;
    }
    void close() override {
        if (h_) CloseHandle(h_); h_ = nullptr;
        pid_ = 0; name_.clear(); regions_.clear();
    }
    bool isOpen() const override { return h_ != nullptr; }
    uint64_t pid() const override { return pid_; }
    std::string name() const override {
        if (!name_.empty()) return name_;
        // exe yolu: ana modul
        if (!regions_.empty()) {
            for (auto& r : regions_) {
                if (r.path.size() > 4 && r.path.rfind(".exe", 0) == std::string::npos) {
                    size_t p = r.path.find_last_of("\\/");
                    if (p != std::string::npos) name_ = r.path.substr(p + 1);
                    break;
                }
            }
        }
        return name_;
    }

    bool read(Addr addr, void* buf, size_t len) override {
        SIZE_T got = 0;
        if (!ReadProcessMemory(h_, (LPCVOID)(uintptr_t)addr, buf, len, &got)) return false;
        return got == len;
    }
    bool readPtrSize(Addr addr, uint64_t& out) override {
        if (is64_) return read(addr, &out, 8);
        uint32_t v = 0;
        if (!read(addr, &v, 4)) return false;
        out = v; return true;
    }
    std::vector<MemRegion> regions() override { return regions_; }

    bool targetIs64() const override { return is64_; }
    int ptrSize() const override { return is64_ ? 8 : 4; }
    Addr ptrMask() const override { return is64_ ? ~(Addr)0 : 0xFFFFFFFFULL; }

    HANDLE handle() const { return h_; }

private:
    void reloadRegions() {
        regions_.clear();
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        Addr p = (Addr)si.lpMinimumApplicationAddress;
        Addr max = (Addr)si.lpMaximumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi{};
        char pathBuf[MAX_PATH * 4];
        while (p < max && VirtualQueryEx(h_, (LPCVOID)(uintptr_t)p, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            Addr start = (Addr)mbi.BaseAddress;
            Addr end = start + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT) {
                MemRegion r;
                r.start = start; r.end = end;
                r.read  = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
                r.write = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
                r.exec  = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE)) != 0;
                r.priv = (mbi.Type == MEM_PRIVATE);
                // yol: dosya eslesmesi — modul ismiyle
                if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                    DWORD sz = GetModuleFileNameExA(h_, (HMODULE)mbi.AllocationBase, pathBuf, MAX_PATH * 4 - 1);
                    if (sz && mbi.Type == MEM_IMAGE) { pathBuf[sz] = 0; r.path = pathBuf; }
                }
                regions_.push_back(r);
            }
            p = end;
        }
    }
    void detectArch() {
        BOOL wow = FALSE;
        is64_ = true;
        if (IsWow64Process(h_, &wow) && wow) is64_ = false;   // 32-bit hedef (wow64)
        else {
            // 64-bit isletim sisteminde kendisi de 64 — header'dan dogrula
            // PE machine check ilk executable image'da
            // (basitlestirilmis: wow64 degilse 64 kabul)
        }
    }

    uint64_t pid_ = 0;
    HANDLE h_ = nullptr;
    std::string name_;
    std::vector<MemRegion> regions_;
    bool is64_ = true;
};

// ------------------------------------------------------------ surec listesi
std::vector<ProcEntry> listProcesses() {
    std::vector<ProcEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcEntry e;
            e.pid = pe.th32ProcessID;
            char nb[256];
            int n = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nb, sizeof(nb), 0, 0);
            e.name = n > 0 ? std::string(nb) : "<noname>";
            out.push_back(e);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::unique_ptr<IProcessReader> openProcess(uint64_t pid) {
    auto p = std::make_unique<WindowsProcess>();
    if (p->open(pid)) return p;
    return nullptr;
}
std::unique_ptr<IProcessReader> openProcessByName(const std::string& name) {
    for (auto& e : listProcesses()) {
        if (e.name.find(name) != std::string::npos) {
            auto p = openProcess(e.pid);
            if (p) return p;
        }
    }
    return nullptr;
}

// ========================================================================
//  PE export tablosu — BELLEKTEN (module.h: loadPeExports)
// ========================================================================
#pragma pack(push, 1)
struct PeDosH { char magic[2]; char _[58]; uint32_t e_lfanew; };
struct PeFileH { uint16_t machine; uint16_t nsec; char _[12]; uint16_t optsz; char _2[2]; };
struct PeOpt64 {
    uint16_t magic; char _[2+2+4+4+4+4+4]; uint32_t szImage; char _3[4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4+4];
    uint32_t dataDir[16 * 2];
};
struct PeSecH {
    char name[8];
    uint32_t vsz, vaddr, rsz, roff, _[4];
    uint32_t chars;
};
#pragma pack(pop)

static bool peRvaToOff(uint32_t rva, const std::vector<PeSecH>& secs, uint32_t& out) {
    for (auto& s : secs) {
        uint32_t sva = s.vaddr, ssize = std::max(s.vsz, s.rsz);
        if (rva >= sva && rva < sva + ssize) { out = s.roff + (rva - sva); return true; }
    }
    return false;
}

bool loadPeExports(IProcessReader& proc, Addr moduleBase, std::vector<Symbol>& out) {
    // DOS
    PeDosH dos{};
    if (!proc.read(moduleBase, &dos, sizeof(dos)) || memcmp(dos.magic, "MZ", 2) != 0) return false;
    // NT
    uint32_t ntf{};
    if (!proc.read(moduleBase + dos.e_lfanew, &ntf, 4) || ntf != 0x00004550) return false;
    PeFileH fh{};
    if (!proc.read(moduleBase + dos.e_lfanew + 4, &fh, sizeof(fh))) return false;
    bool pe32p = (fh.machine == 0x8664);
    Addr opt = moduleBase + dos.e_lfanew + 4 + sizeof(PeFileH);
    // data directory: +96 (pe32+) veya +92+? (pe32) — pe32: export dir @ opt+96
    Addr expDirRvaAddr = pe32p ? opt + 112 : opt + 96;   // DataDirectory[0] (export)
    uint32_t expRva{}, expSz{};
    if (!proc.read(expDirRvaAddr, &expRva, 4) || !proc.read(expDirRvaAddr + 4, &expSz, 4))
        return false;
    if (!expRva || !expSz) return false;   // export yok
    // bolumler
    std::vector<PeSecH> secs(fh.nsec);
    Addr secBase = opt + fh.optsz;
    if (!proc.read(secBase, secs.data(), (size_t)fh.nsec * sizeof(PeSecH))) return false;

    uint32_t expOff{};
    if (!peRvaToOff(expRva, secs, expOff)) return false;
    Addr exp = moduleBase + expOff;
    uint32_t nameRva{}, funcsRva{}, namesRva{}, ordsRva{}, nNames{};
    if (!proc.read(exp + 12, &nameRva, 4) || !proc.read(exp + 28, &nNames, 4) ||
        !proc.read(exp + 32, &funcsRva, 4) || !proc.read(exp + 36, &namesRva, 4) ||
        !proc.read(exp + 40, &ordsRva, 4))
        return false;
    if (!nNames || nNames > 200000) return false;
    uint32_t namesOff{}, funcsOff{}, ordsOff{};
    if (!peRvaToOff(namesRva, secs, namesOff) || !peRvaToOff(funcsRva, secs, funcsOff) ||
        !peRvaToOff(ordsRva, secs, ordsOff))
        return false;
    Addr names = moduleBase + namesOff, funcs = moduleBase + funcsOff, ords = moduleBase + ordsOff;

    char nm[512];
    for (uint32_t i = 0; i < nNames; i++) {
        uint32_t nrva{}, ord16{};
        if (!proc.read(names + i * 4, &nrva, 4)) break;
        uint32_t noff{};
        if (!peRvaToOff(nrva, secs, noff)) continue;
        if (!proc.read(moduleBase + noff, nm, sizeof(nm) - 1)) continue;
        nm[sizeof(nm) - 1] = 0;
        // uzunluk
        size_t len = 0; while (len < sizeof(nm) - 1 && nm[len]) len++;
        if (!len) continue;
        if (!proc.read(ords + i * 2, &ord16, 2)) continue;
        uint32_t frva{};
        if (!proc.read(funcs + ord16 * 4, &frva, 4)) continue;
        Symbol s;
        s.address = moduleBase + frva;
        s.name.assign(nm, len);
        s.type = 'T';
        out.push_back(std::move(s));
    }
    return !out.empty();
}

} // namespace umvpqt

#endif // _WIN32
