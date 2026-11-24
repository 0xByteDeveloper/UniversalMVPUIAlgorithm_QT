// UMVPQT GOD STATE — Module / Symbol layer
// ============================================================================
//  Hedef surecin modulleri + sembol cozumleme:
//    Linux : /proc maps yollari + diskteki ELF .dynsym parse  (hizli + guvenli)
//            (dosya yoksa: bellekteki ELF parse fallback)
//    Win   : Bellekteki PE export tablosu parse (Toolhelp32 module listesi)
//  Semboller: vtable for X (_ZTV7X / ??_7X@@6B@), staticMetaObject, qVersion...
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include <string>
#include <vector>
#include <functional>

namespace umvpqt {

class ModuleTable {
public:
    // Surecin tum modullerini yukle + sembolleri coz
    bool load(IProcessReader& proc);

    const std::vector<Module>& modules() const { return mods_; }

    // Verilen adresin modulu
    const Module* moduleOf(Addr addr) const;
    // Ada gore modul (tam isim veya iceren)
    const Module* byName(const std::string& contains) const;

    // Sembol cozumleme (Qt modulleri + ana exe)
    const Symbol* findSymbol(const Module& m, const std::string& exactName) const;
    const Symbol* findSymbolAny(const std::string& exactName, std::string* moduleOut = nullptr) const;
    // "vtable for QWidget" tarzi: class -> vtable adresi (Itenanium: _ZTV<len><name>)
    Addr vtableOf(const std::string& className, std::string* moduleOut = nullptr) const;
    Addr staticMetaObjectOf(const std::string& className, std::string* moduleOut = nullptr) const;
    Addr qVersionFn(std::string* moduleOut = nullptr) const;

    // Bir adres icinde bulundugu sembolu bul (en yakin kucuk baslangicli)
    const Symbol* symbolAt(Addr addr, const Module* within = nullptr) const;

private:
    std::vector<Module> mods_;
    IProcessReader* proc_ = nullptr;
};

// ---- Itanium (Linux) mangling yardimcilari ----
// "_ZTV7QWidget" -> class adi "QWidget" cikar; "_ZTVN..." ic ice (ns) destekli
bool itaniumVtableClassName(const std::string& sym, std::string& outClass);
std::string itaniumVtableSymbol(const std::string& className);   // _ZTV<len><name>
std::string itaniumStaticMetaObjectSymbol(const std::string& className);
// "_ZN12QMainWindow16staticMetaObjectE" parse
bool itaniumStaticMetaObjectClassName(const std::string& sym, std::string& outClass);

// ---- MSVC mangling (Windows) ----
// "??_7QWidget@@6B@" -> "QWidget"
bool msvcVtableClassName(const std::string& sym, std::string& outClass);
std::string msvcVtableSymbol(const std::string& className);
std::string msvcStaticMetaObjectSymbol(const std::string& className);

// ---- ELF dosyadan .dynsym yukle (Linux) ----
//  file: diskteki .so / exe yolu;  mapBase: surecteki taban adres
//  fallbackInMemory: dosya okunamiyorsa bellekten ELF parse
bool loadElfSymbols(const std::string& file, Addr mapBase, Addr vaddrStart, Addr vaddrEnd,
                    std::vector<Symbol>& out, IProcessReader* proc = nullptr);

// ---- PE export tablosu (bellekten, Windows) ----
bool loadPeExports(IProcessReader& proc, Addr moduleBase, std::vector<Symbol>& out);

} // namespace umvpqt
