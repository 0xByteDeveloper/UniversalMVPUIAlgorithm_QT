// UMVPQT GOD STATE — Capstone Disassembly Engine
// ============================================================================
//  - qt_static_metacall switch cozumlemesi: metod index -> slot fonksiyon adresi
//    (GOD: her sinifin metotlarinin GERCEK kod adresleri PDB'siz cikarilir)
//  - fonksiyon sinirlari: sembol tablosundan (bir sonraki sembol) + ret hizasi
//  - .asm dump (XPRO report.h .asm cikti tarzi)
//  - override tespiti icin vtable slot karsilastirma destegi
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "module.h"
#include <string>
#include <map>
#include <vector>

namespace umvpqt {

struct DisasmEngine {
    IProcessReader* proc = nullptr;
    ModuleTable* mt = nullptr;
    bool x86_64 = true;

    // ---- capstone init ----
    bool init(IProcessReader& p, ModuleTable& m);
    ~DisasmEngine();

    // metacall: InvokeMetaMethod switch'ini cöz: id -> hedef fonksiyon
    // (call rel32 / call [rip+X] PLT deseni tespiti)
    std::map<int, Addr> parseMetacall(Addr fn, int methodCount);

    // fonksiyon siniri: sembol siralamasindan [start, end)
    bool functionExtent(Addr start, Addr& end);

    // disassembly metni uret (start..end, maxInsn adet)
    std::string disasmText(Addr start, Addr end, size_t maxInsn = 512);

    // bir adresteki hedefi cöz: jmp/call rel32 -> gercek adres
    Addr resolveCallTarget(Addr callSite);

private:
    void* csHandle = nullptr;   // csh (capstone)
    void* insn = nullptr;
    struct Impl;
    Impl* impl = nullptr;
};

// QWidget sanal slot indeksleri — sembollerden AMPRIK tespit:
//   QWidget::paintEvent adresi QWidget vtable'inde kacinci slot?
// (sabit kod yerine bellekten olculur — Qt surumunden bagimsiz)
struct VirtualSlotMap {
    // virtual adi -> (vtable index, base implementation address)
    std::map<std::string, std::pair<int, Addr>> slots;   // QWidget vtable
    IProcessReader* proc = nullptr;

    // QWidget vtable + QWidget::paintEvent vb. sembollerinden olustur
    bool build(IProcessReader& proc, ModuleTable& mt, const std::string& baseClass = "QWidget");

    // verilen nesne vtable'inde override var mi? varsa adresi don
    Addr overridden(Addr vtable, const std::string& virtName);
};

} // namespace umvpqt
