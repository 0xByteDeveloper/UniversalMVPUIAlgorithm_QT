// UMVPQT GOD STATE — Remote Invoke Engine (uzaktan cagri motoru)
// ============================================================================
//  Hedef surece KOD CALISTIRMA katmani — "button1'e basilsin" sorusunun
//  gercek cevabi: harici bellek YAZMA + uzak fonksiyon cagrisi.
//
//  Katman 1 — IInvoker (platform soyutlamasi):
//    Linux  : ptrace tabanli (PTRACE_SEIZE + PTRACE_INTERRUPT + register
//             kurtarma + mmap enjeksiyonu) — GUI thread'i KENDI is parcacigi
//             uzerinde cagri calistirir (Qt thread-affinity guvenli).
//    Windows: CreateRemoteThread + RWX stub (mov rcx,this; ...; call fn)
//             + PostMessage(WM_LBUTTONDOWN/UP) "güvenli tiklama" modu.
//
//  Katman 2 — QtActor (yuksek seviye Qt aksiyonlari):
//    Qt DLL/so EXPORT sembolleri uzerinden:
//      QAbstractButton::click()          — buton tikla
//      QAbstractButton::setChecked(bool) — checkbox degistir
//      QComboBox::setCurrentIndex(int)   — combobox deger sec
//      QLineEdit::setText(QString)       — metin yaz (QString uzaktan kur)
//      QListWidget::setCurrentRow(int)    — listeden satir sec
//      QTabWidget::setCurrentIndex(int)  — tab degistir
//    Sembol: Itanium (_ZN13QAbstractButton5clickEv) + MSVC
//            (?click@QAbstractButton@@QEAAXXZ) + isim-icerek taramasi.
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "module.h"
#include "qt_layouts.h"
#include "qt_scan.h"

namespace umvpqt {

struct RemoteCallResult {
    bool        ok = false;       // cagri tamamlandi
    bool        pending = false;  // zaman asimi — hala calisiyor (modal acik!)
    uint64_t    ret = 0;          // donus degeri (RAX)
    std::string error;            // hata aciklamasi
};

class IInvoker {
public:
    virtual ~IInvoker() = default;

    // ---- temel kabiliyetler ----
    // Uzak fonksiyon cagrisi: fn(thisPtr, a1, a2, a3) ABI'ine gore eslenir.
    virtual RemoteCallResult callFn(Addr fn, Addr thisPtr,
                                     uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0,
                                     int timeoutMs = 5000) = 0;
    // V3.2 — wine altindaki Windows PE kodu Microsoft x64 ABI'si kullanir
    // (rcx/rdx/r8/r9). Linux ELF hedef SysV (rdi/rsi/rdx/rcx). Bu anahtar
    // yoksa Linux ELF uzak cagrilarina zarar verir (yalniz acikken degisir).
    virtual void setWin64Convention(bool on) { (void)on; }
    // Hedef surecte RW (Linux) / RWX (Win stub) sayfa ayir
    virtual Addr remoteAlloc(size_t size) = 0;
    // Hedef bellege yaz / oku
    virtual bool remoteWrite(Addr addr, const void* data, size_t len) = 0;
    virtual bool remoteRead(Addr addr, void* buf, size_t len) = 0;

    // ---- durum ----
    virtual bool hasPendingCall() const = 0;   // iptal edilmesi gereken cagri var mi
    // GUI thread'i hedefe geri birak (komutlar arasi — ptrace modunda kritik)
    virtual void releaseThread() {}
    // bekleme dongulerinde bitmis pending cagrileri topla
    virtual void pollPending() {}
    virtual std::string platform() const = 0;
    virtual std::string lastError() const { return lastErr_; }

protected:
    std::string lastErr_;
};

// ---------------------------------------------------------------- factory --
// Platform'a uygun invoker kurar (Linux: ptrace, Windows: remote thread)
std::unique_ptr<IInvoker> createInvoker(IProcessReader& proc);

// ---------------------------------------------------------------- QtActor --
// Yuksek seviye Qt kontrol motoru (sembol cozumlu, PDB'siz)
struct QtActor {
    IProcessReader* proc = nullptr;   // Analyzer'dan
    ModuleTable*    mt = nullptr;
    const QtLayouts* L = nullptr;
    ClassRegistry*  reg = nullptr;
    IInvoker*       inv = nullptr;
    int             defaultTimeoutMs = 5000;

    // ---- sembol cozumleme ----
    // Qt modul sembollerinde "class::method" export'unu bul.
    // Sirasiyla: Itanium prefix, MSVC prefix, isim-icerik taramasi.
    Addr resolveMethod(const std::string& className, const std::string& method,
                       std::string* symNameOut = nullptr);

    // ---- temel invoke ----
    RemoteCallResult invokeMethod(Addr objAddr, const std::string& className,
                                  const std::string& method,
                                  uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0,
                                  int timeoutMs = -1);

    // ---- V3.2 — STATİK Qt slot invoke (qt_static_metacall yolu) ----
    // Export tablosu olmayan (Qt'i statik gömülü — VMProtect gibi) hedeflerde
    // "Class::slot" çağrısı: qt_static_metacall(_o, InvokeMetaMethod, _id, _a).
    // MainWindow::addFunction() / MainWindow::compile() gibi NO-ARG slotlar
    // doğrudan tetiklenir — ekran görüntüsü/event'i yok, salt bellek çağrısı.
    // strArg: tek QString parametreli slotlar için (QLineEdit::setText gibi)
    // argv[1] hedefte kurulan QString'e işaret eder.
    RemoteCallResult callSlot(Addr objAddr, const std::string& slotName, int timeoutMs = -1,
                              const std::string* strArg = nullptr);

    // ---- yuksek seviye aksiyonlar ----
    // hepsi: nesnenin sinif zinciri className icerir + export sembolu bulunur
    RemoteCallResult click(Addr widget, int timeoutMs = -1);
    RemoteCallResult setChecked(Addr widget, bool on, int timeoutMs = -1);
    RemoteCallResult setComboIndex(Addr combo, int index, int timeoutMs = -1);
    RemoteCallResult setText(Addr lineEdit, const std::string& utf8, int timeoutMs = -1);
    RemoteCallResult selectRow(Addr listWidget, int row, int timeoutMs = -1);
    RemoteCallResult setTab(Addr tabWidget, int index, int timeoutMs = -1);

    // ---- QString'i HEDEF surecte kur (Qt5: [d]; Qt6: [d][ptr][size]) ----
    // Basariysa QString nesnesinin hedef adresi. Kopya guvenli (ref=-1 statik).
    Addr makeQString(const std::string& utf8, std::string* err = nullptr);

    // ---- yardimci ----
    bool chainHas(Addr objAddr, const std::string& cls);
};

} // namespace umvpqt
