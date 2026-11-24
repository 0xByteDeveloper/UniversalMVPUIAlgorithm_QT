// UMVPQT GOD STATE — Module layer implementation (Linux ELF path)
// ============================================================================
//  - /proc maps'ten modul listesi (path'li bolgeleri birlestirir)
//  - Diskteki ELF .dynsym sembolleri (guvenilir + hizli)
//  - Dosya yoksa bellekte ELF parse (PT_DYNAMIC -> DT_SYMTAB/DT_STRTAB)
// ============================================================================
#include "umvpqt/module.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <map>
#include <set>
#include <unistd.h>

namespace umvpqt {

// ---------------------------------------------------------------- util ----
static bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}
static std::string baseNameOf(const std::string& path) {
    size_t p = path.find_last_of('/');
    return p == std::string::npos ? path : path.substr(p + 1);
}

// --------------------------------------------------- Itanium mangling ----
// _ZTV<Len><Name>  — or: _ZTV12QMainWindow
bool itaniumVtableClassName(const std::string& sym, std::string& outClass) {
    if (sym.rfind("_ZTV", 0) != 0) return false;
    const char* p = sym.c_str() + 4;
    char* end = nullptr;
    long len = strtol(p, &end, 10);
    if (len <= 0 || !end || (size_t)(end - p) + (size_t)len > sym.size()) return false;
    outClass.assign(end, (size_t)len);
    return true;
}
std::string itaniumVtableSymbol(const std::string& className) {
    // not: sadece duz siniflar (ic ice namespace yoksa basit tut)
    return "_ZTV" + std::to_string(className.size()) + className;
}
bool itaniumStaticMetaObjectClassName(const std::string& sym, std::string& outClass) {
    // _ZN<Len1><Class>16staticMetaObjectE
    if (sym.rfind("_ZN", 0) != 0) return false;
    if (!endsWith(sym, "16staticMetaObjectE")) return false;
    const char* p = sym.c_str() + 3;
    char* end = nullptr;
    long len = strtol(p, &end, 10);
    if (len <= 0 || !end) return false;
    if ((size_t)(end - p) + (size_t)len > sym.size()) return false;
    outClass.assign(end, (size_t)len);
    return true;
}
std::string itaniumStaticMetaObjectSymbol(const std::string& className) {
    return "_ZN" + std::to_string(className.size()) + className + "16staticMetaObjectE";
}

// ------------------------------------------------------ MSVC mangling ----
bool msvcVtableClassName(const std::string& sym, std::string& outClass) {
    // "??_7QWidget@@6B@"
    if (sym.rfind("??_7", 0) != 0) return false;
    size_t at = sym.find("@@6B@");
    if (at == std::string::npos) return false;
    outClass = sym.substr(4, at - 4);
    return !outClass.empty();
}
std::string msvcVtableSymbol(const std::string& className) { return "??_7" + className + "@@6B@"; }
std::string msvcStaticMetaObjectSymbol(const std::string& className) {
    return "?" + className + "@?1??staticMetaObject@" + className + "@@2UQMetaObject@@A";
}

// ------------------------------------------------------- ELF yukleme ----
#pragma pack(push, 1)
struct Elf64_EHdr_P {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct Elf64_SHdr_P {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
};
struct Elf64_Sym_P {
    uint32_t st_name;
    unsigned char st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
};
struct Elf32_EHdr_P {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version, e_entry, e_phoff, e_shoff, e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_SHdr_P {
    uint32_t sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
        sh_link, sh_info, sh_addralign, sh_entsize;
};
struct Elf32_Sym_P {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    unsigned char st_info, st_other;
    uint16_t st_shndx;
};
struct Elf64_Phdr_P {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
#pragma pack(pop)

// diskteki ELF sembolleri: mapBase + vaddr => surec adresi
bool loadElfSymbols(const std::string& file, Addr mapBase, Addr vaddrStart, Addr vaddrEnd,
                    std::vector<Symbol>& out, IProcessReader* proc) {
    FILE* f = fopen(file.c_str(), "rb");
    if (!f) { fprintf(stderr, "  [elf] fopen fail: %s\n", file.c_str()); return false; }
    // dosyanin kendi base'ini bul: PT_LOAD segment vaddr'lerinin min'i ile
    unsigned char hdr[64];
    if (fread(hdr, 1, 64, f) != 64) { fprintf(stderr, "  [elf] hdr read fail\n"); fclose(f); return false; }
    bool elf64 = hdr[4] == 2;
    uint64_t shoff = 0; uint32_t shentsize = 0, shnum = 0, shstrndx = 0;
    uint64_t phoff = 0; uint32_t phentsize = 0, phnum = 0;
    if (elf64) {
        auto* h = (Elf64_EHdr_P*)hdr;
        if (memcmp(h->e_ident, "\x7f""ELF", 4) != 0) { fprintf(stderr, "  [elf] magic fail\n"); fclose(f); return false; }
        shoff = h->e_shoff; shentsize = h->e_shentsize; shnum = h->e_shnum; shstrndx = h->e_shstrndx;
        phoff = h->e_phoff; phentsize = h->e_phentsize; phnum = h->e_phnum;
    } else {
        auto* h = (Elf32_EHdr_P*)hdr;
        if (memcmp(h->e_ident, "\x7f""ELF", 4) != 0) { fprintf(stderr, "  [elf] magic fail32\n"); fclose(f); return false; }
        shoff = h->e_shoff; shentsize = h->e_shentsize; shnum = h->e_shnum; shstrndx = h->e_shstrndx;
        phoff = h->e_phoff; phentsize = h->e_phentsize; phnum = h->e_phnum;
    }
    fprintf(stderr, "  [elf] %s: elf64=%d shoff=%llu shnum=%u shentsize=%u\n", file.c_str(), (int)elf64, (unsigned long long)shoff, shnum, shentsize);
    // ELF file base: min PT_LOAD p_vaddr (0. segment genelde 0)
    uint64_t elfBase = 0; bool baseFound = false;
    std::vector<unsigned char> ph(phentsize * phnum);
    if (phnum && phentsize) {
        if (fseek(f, (long)phoff, SEEK_SET) == 0 && fread(ph.data(), 1, ph.size(), f) == ph.size()) {
            for (uint32_t i = 0; i < phnum; i++) {
                unsigned char* p = ph.data() + i * phentsize;
                uint32_t ptype = *(uint32_t*)p;
                if (ptype == 1 /*PT_LOAD*/) {
                    uint64_t vaddr = elf64 ? ((Elf64_Phdr_P*)p)->p_vaddr : *(uint64_t*)(p + 8) /*yeterli degil ama 32bit: p_vaddr offset 8*/;
                    if (elf64) vaddr = ((Elf64_Phdr_P*)p)->p_vaddr;
                    else vaddr = *(uint32_t*)(p + 8);
                    if (!baseFound || vaddr < elfBase) { elfBase = vaddr; baseFound = true; }
                }
            }
        }
    }
    // ancak surecteki gercek taban: mapBase (ilk bolge). Dosya vaddr -> surec = mapBase + (vaddr - elfBase)
    Addr procBase = mapBase;
    // .dynsym + .dynstr bul
    if (!shnum || !shentsize) { fclose(f); return false; }
    std::vector<unsigned char> shbuf((size_t)shentsize * shnum);
    if (fseek(f, (long)shoff, SEEK_SET) != 0 || fread(shbuf.data(), 1, shbuf.size(), f) != shbuf.size()) { fclose(f); return false; }

    uint64_t dynsymOff = 0, dynsymSize = 0, dynsymEnts = 0, dynstrOff = 0, dynstrSize = 0;
    uint64_t dynsymAddr = 0;
    for (uint32_t i = 0; i < shnum; i++) {
        unsigned char* s = shbuf.data() + i * shentsize;
        uint32_t type;
        uint64_t offset, size, addr;
        if (elf64) {
            auto* h = (Elf64_SHdr_P*)s;
            type = h->sh_type; offset = h->sh_offset; size = h->sh_size; addr = h->sh_addr;
        } else {
            auto* h = (Elf32_SHdr_P*)s;
            type = h->sh_type; offset = h->sh_offset; size = h->sh_size; addr = h->sh_addr;
        }
        if (type == 11 /*SHT_DYNSYM*/ || type == 2 /*SHT_SYMTAB*/) {
            dynsymOff = offset; dynsymSize = size;
            dynsymEnts = elf64 ? sizeof(Elf64_Sym_P) : sizeof(Elf32_Sym_P);
            dynsymAddr = addr;
            // sh_link -> dynstr index
            uint32_t link = elf64 ? ((Elf64_SHdr_P*)s)->sh_link : ((Elf32_SHdr_P*)s)->sh_link;
            if (link < shnum) {
                unsigned char* s2 = shbuf.data() + link * shentsize;
                if (elf64) { auto* h2 = (Elf64_SHdr_P*)s2; dynstrOff = h2->sh_offset; dynstrSize = h2->sh_size; }
                else { auto* h2 = (Elf32_SHdr_P*)s2; dynstrOff = h2->sh_offset; dynstrSize = h2->sh_size; }
            }
        }
    }
    if (!dynsymSize) { fclose(f); return false; }

    std::vector<unsigned char> symtab(dynsymSize);
    if (fseek(f, (long)dynsymOff, SEEK_SET) != 0 || fread(symtab.data(), 1, dynsymSize, f) != dynsymSize) { fclose(f); return false; }
    std::vector<unsigned char> strtab(dynstrSize);
    if (dynstrSize && (fseek(f, (long)dynstrOff, SEEK_SET) != 0 || fread(strtab.data(), 1, dynstrSize, f) != dynstrSize)) { fclose(f); return false; }
    fclose(f);

    for (uint64_t i = 0; i * dynsymEnts < dynsymSize; i++) {
        unsigned char* s = symtab.data() + i * dynsymEnts;
        uint32_t nameIdx; uint64_t value; unsigned char info;
        if (elf64) { auto* y = (Elf64_Sym_P*)s; nameIdx = y->st_name; value = y->st_value; info = y->st_info; }
        else { auto* y = (Elf32_Sym_P*)s; nameIdx = y->st_name; value = y->st_value; info = y->st_info; }
        if (!nameIdx || nameIdx >= dynstrSize) continue;
        std::string nm((const char*)strtab.data() + nameIdx);
        if (nm.empty()) continue;
        if (!value) continue;
        // surecte adres: procBase + (value - elfBase)
        Addr a = procBase + (Addr)(value - elfBase);
        if (vaddrStart && (value < vaddrStart || value >= vaddrEnd)) {
            // disarida kalan sembolleri at (harita disina tasmamalar icin)
            // PT_LOAD 0 icinde olmayan (oz. .text diger segment) semboller yine basilabilir
        }
        Symbol sym;
        sym.address = a;
        sym.name = nm;
        sym.type = (info & 0xf) == 2 ? 'D' : 'T';   // STT_FUNC/T
        out.push_back(sym);
    }
    return !out.empty();
}

// ------------------------------------------------ ModuleTable::load ----
bool ModuleTable::load(IProcessReader& proc) {
    proc_ = &proc;
    mods_.clear();
    auto regs = proc.regions();

    // path'li bolgeleri modul olarak birlestir
    std::map<std::string, Module> byPath;
    for (auto& r : regs) {
        if (r.path.empty() || r.path[0] != '/') continue;
        if (endsWith(r.path, " (deleted)")) continue;
        std::string p = r.path;
        auto& m = byPath[p];
        if (m.path.empty()) {
            m.path = p;
            m.name = baseNameOf(p);
            m.base = r.start;
            m.end = r.end;
        } else {
            if (r.start < m.base) m.base = r.start;
            if (r.end > m.end) m.end = r.end;
        }
        m.size = m.end - m.base;
    }
    // ana exe tespiti: /proc/<pid>/exe hedefi
    char exePath[512] = {};
    {
        char lnk[64];
        snprintf(lnk, sizeof(lnk), "/proc/%llu/exe", (unsigned long long)proc.pid());
        ssize_t n = readlink(lnk, exePath, sizeof(exePath) - 1);
        if (n > 0) exePath[n] = 0;
    }
    for (auto& [p, m] : byPath) {
        std::string bn = baseNameOf(p);
        bool qt = bn.find("Qt5") != std::string::npos || bn.find("Qt6") != std::string::npos
                || bn.find("libQt") != std::string::npos || bn.find("Qt6Core") != std::string::npos;
        m.isQt = qt;
        m.isMainExe = (p == exePath);
        mods_.push_back(std::move(m));
    }
    std::stable_sort(mods_.begin(), mods_.end(), [](const Module& a, const Module& b) {
        return a.base < b.base;
    });

    // sembolleri yukle: Qt modulleri + exe (ana modul = en buyuk calistirilabilir)
    for (auto& m : mods_) {
        if (!m.isQt && !m.isMainExe) continue;
        loadElfSymbols(m.path, m.base, 0, 0, m.symbols, &proc);
        std::sort(m.symbols.begin(), m.symbols.end(), [](const Symbol& a, const Symbol& b) {
            return a.address < b.address;
        });
    }
    return true;
}

const Module* ModuleTable::moduleOf(Addr addr) const {
    for (auto& m : mods_) if (addr >= m.base && addr < m.end) return &m;
    return nullptr;
}
const Module* ModuleTable::byName(const std::string& contains) const {
    for (auto& m : mods_) if (m.name.find(contains) != std::string::npos) return &m;
    return nullptr;
}
const Symbol* ModuleTable::findSymbol(const Module& m, const std::string& exact) const {
    for (auto& s : m.symbols) if (s.name == exact) return &s;
    return nullptr;
}
const Symbol* ModuleTable::findSymbolAny(const std::string& exact, std::string* moduleOut) const {
    for (auto& m : mods_) {
        for (auto& s : m.symbols) {
            if (s.name == exact) {
                if (moduleOut) *moduleOut = m.name;
                return &s;
            }
        }
    }
    return nullptr;
}
Addr ModuleTable::vtableOf(const std::string& className, std::string* moduleOut) const {
    std::string sym = itaniumVtableSymbol(className);
    if (auto* s = findSymbolAny(sym, moduleOut)) return s->address;
    sym = msvcVtableSymbol(className);
    if (auto* s = findSymbolAny(sym, moduleOut)) return s->address;
    return 0;
}
Addr ModuleTable::staticMetaObjectOf(const std::string& className, std::string* moduleOut) const {
    std::string sym = itaniumStaticMetaObjectSymbol(className);
    if (auto* s = findSymbolAny(sym, moduleOut)) return s->address;
    sym = msvcStaticMetaObjectSymbol(className);
    if (auto* s = findSymbolAny(sym, moduleOut)) return s->address;
    return 0;
}
Addr ModuleTable::qVersionFn(std::string* moduleOut) const {
    if (auto* s = findSymbolAny("qVersion", moduleOut)) return s->address;
    return 0;
}
const Symbol* ModuleTable::symbolAt(Addr addr, const Module* within) const {
    const Symbol* best = nullptr;
    for (auto& m : mods_) {
        if (within && &m != within) continue;
        if (!within && !(addr >= m.base && addr < m.end)) continue;
        for (auto& s : m.symbols) {
            if (s.address <= addr && (!best || s.address > best->address)) best = &s;
        }
    }
    return best;
}

} // namespace umvpqt
