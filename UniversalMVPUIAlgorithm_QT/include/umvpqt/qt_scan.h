// UMVPQT GOD STATE — Qt Detection + QObject Instance Scanner
// ============================================================================
//  1) QtDetector   : Qt var mi? hangi cag/surum? (modul isimleri + qVersion
//                    disassembly + metaobject revision imzasi)
//  2) InstanceScan : heap taramasi — q_ptr geri-bag INVARIANT'i:
//                       X bir QObject <=> *(X+ptr) = D ve *(D+q_ptr) == X
//  3) ClassResolve : vtable -> sinif (sembol vtable tablosu veya
//                    vtable[metaObject-slot] thunk cozumlemesi)
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "module.h"
#include "qt_layouts.h"
#include "qt_strings.h"
#include "qt_metaobject.h"

namespace umvpqt {

// ---------------------------------------------------------------- tespit --
struct QtDetector {
    // Qt'i tespit et; tam surumu cozmeye calisir.
    static bool detect(IProcessReader& proc, ModuleTable& mt, const QtLayouts& L,
                       QtInfo& out);

    // qVersion() export'unun kucuk fonksiyonunu disasm edip
    // "x.y.z" string isaretcisini ceker (mov rax,[rip+X]; ret)
    static std::string versionViaQVersion(IProcessReader& proc, ModuleTable& mt);
    // Core modul rodata'sinda "N.N.N" surum imzasi ara
    static std::string versionViaScan(IProcessReader& proc, const Module& core);
};

// ------------------------------------------------- vtable thunk cozumleme --
// vtable[slot0] = metaObject() thunk: "mov rax,[rip+d]; ret" -> QMetaObject*
// 64-bit desen: 48 8B 05 ?? ?? ?? ?? C3
// 32-bit desen: B8 05 00 00 00 (mov eax, imm32) — hmm; A1 <imm32> (mov eax,moffs) c3
Addr resolveMetaObjectFromVtable(IProcessReader& proc, Addr vtable, bool* ok);

// ------------------------------------------------------ sinif cozumleme --
struct ClassRegistry {
    // vtable -> sinif adi (Qt modul sembolleri + metaobject thunk + RTTI)
    std::map<Addr, MetaClassInfo> byVtable;
    std::map<Addr, MetaClassInfo> byMetaObject;   // cache: parse edilmis

    IProcessReader* proc = nullptr;
    const QtLayouts* L = nullptr;
    const ModuleTable* mt = nullptr;
    MetaObjectParser* moParser = nullptr;

    // vtable icin sinif bilgisi (cache'li). nullptr dönerse sinif cozulemedi.
    const MetaClassInfo* resolveVtable(Addr vtable);
    // metaObject adresinin sinif adi (cache'li)
    const MetaClassInfo* resolveMetaObject(Addr mo);

    // RTTI ile sinif adi (Q_OBJECT'suz app siniflari): vtable[-1] -> typeinfo
    // Itanium: typeinfo { vptr, name* } -> "N12MyWidgetE"
    std::string classNameViaRtti(Addr vtable);

    // Sinif, QWidget turevli mi? (superdata zinciri QWidget::staticMetaObject'a ulasir)
    bool isWidgetClass(const MetaClassInfo& ci) const;
    // Zincirde belirtilen sinif var mi?
    bool chainContains(const MetaClassInfo& ci, const std::string& cls) const;

    Addr qwidgetStaticMetaObject = 0;   // tespitte doldurulur (isWidget hizlandirma)
};

// Itanium tip adini demangle et: "N12MyWidgetE" -> "MyWidget"
std::string demangleItanium(const char* name);

// ---------------------------------------------------- heap tarama motoru --
struct InstanceScan {
    // Tum RW-anonim bolgeleri tara; QObject instance adreslerini dondurur.
    // maxRegions: guvenlik siniri; alignment = ptrSize.
    static std::vector<Addr> scanQObjects(IProcessReader& proc, const QtLayouts& L,
                                          const ModuleTable& mt,
                                          size_t maxBytesPerRegion = 256ull * 1024 * 1024);

    // Tek bir adresteki QObject'i dogrula (q_ptr geri-bag)
    static bool isValidQObject(IProcessReader& proc, const QtLayouts& L, Addr x,
                               Addr* dOut = nullptr, Addr* vtableOut = nullptr);
};

} // namespace umvpqt
