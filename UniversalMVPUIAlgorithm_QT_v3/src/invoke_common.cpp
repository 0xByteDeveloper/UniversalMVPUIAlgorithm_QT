// UMVPQT GOD STATE — QtActor: yuksek seviye Qt kontrol motoru (ortak katman)
// ============================================================================
//  Qt DLL/so EXPORT sembolleri PDB'siz cozulur (Itanium + MSVC + tarama):
//    QAbstractButton::click()          — buton tikla
//    QAbstractButton::setChecked(bool)  — checkbox degistir
//    QComboBox::setCurrentIndex(int)    — combobox deger sec
//    QLineEdit::setText(QString)       — metin yaz (QString HEDEpte kurulur)
//    QListWidget::setCurrentRow(int)    — listeden satir sec
//    QTabWidget::setCurrentIndex(int)   — tab degistir
//  + makeQString: hedef surecte gecerli QString nesnesi kur (Qt5/Qt6 farkli).
// ============================================================================
#include "umvpqt/invoke.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace umvpqt {

// ---------------------------------------------------------------- sembol --
// "QComboBox::setCurrentIndex" export'unu bul.
//  0) bilinen tam mangled isimler (overload tuzağına düşmemek için)
//  1) Itanium prefix: _ZN<clsLen><class><mthLen><method>
//  2) MSVC prefix   : ?<method>@<class>@@
//  3) isim icerigi  : sinif + metod ikisi de gecen sembol
Addr QtActor::resolveMethod(const std::string& className, const std::string& method,
                            std::string* symNameOut) {
    if (!mt) return 0;

    // ---- pass 0: bilinen kesin imzalar ----
    static const struct { const char* cls; const char* mth; const char* mangled; } exact[] = {
        { "QAbstractButton", "click",        "_ZN13QAbstractButton5clickEv" },
        { "QAbstractButton", "setChecked",   "_ZN13QAbstractButton9setCheckedEb" },
        { "QComboBox",       "setCurrentIndex", "_ZN9QComboBox14setCurrentIndexEi" },
        { "QComboBox",       "setCurrentText",  "_ZN9QComboBox14setCurrentTextERK7QString" },
        { "QLineEdit",      "setText",      "_ZN9QLineEdit7setTextERK7QString" },
        { "QListWidget",    "setCurrentRow", "_ZN11QListWidget13setCurrentRowEi" },
        { "QTabWidget",     "setCurrentIndex", "_ZN10QTabWidget14setCurrentIndexEi" },
        { "QCheckBox",      "setChecked",   "_ZN8QCheckBox9setCheckedEb" },
        { nullptr, nullptr, nullptr }
    };
    for (int i = 0; exact[i].cls; i++) {
        if (className == exact[i].cls && method == exact[i].mth) {
            if (auto* s = mt->findSymbolAny(exact[i].mangled, symNameOut ? nullptr : nullptr)) {
                if (symNameOut) *symNameOut = exact[i].mangled;
                return s->address;
            }
        }
    }

    std::string itanium = "_ZN" + std::to_string(className.size()) + className +
                          std::to_string(method.size()) + method;
    std::string msvc = "?" + method + "@" + className + "@@";

    for (int pass = 1; pass < 4; pass++) {
        for (auto& m : mt->modules()) {
            if (!m.isQt && !m.isMainExe) continue;
            for (auto& s : m.symbols) {
                bool hit = false;   // (tip filtresi yok: module.cpp STT_FUNC'i 'D' olarak etiketler)
                if (pass == 1) hit = s.name.rfind(itanium, 0) == 0;
                else if (pass == 2) hit = s.name.rfind(msvc, 0) == 0;
                else {
                    hit = s.name.find(className) != std::string::npos &&
                         s.name.find(method) != std::string::npos;
                }
                if (hit) {
                    if (symNameOut) *symNameOut = s.name;
                    return s.address;
                }
            }
        }
    }
    return 0;
}

// ------------------------------------------------------------ chainHas ----
bool QtActor::chainHas(Addr objAddr, const std::string& cls) {
    if (!proc || !reg) return false;
    Addr vt = proc->readAddr(objAddr);
    if (!vt) return false;
    const MetaClassInfo* ci = reg->resolveVtable(vt);
    if (!ci) return false;
    if (ci->className == cls || ci->classNameResolved == cls) return true;
    return reg->chainContains(*ci, cls);
}

// ---------------------------------------------------------- invokeMethod --
RemoteCallResult QtActor::invokeMethod(Addr objAddr, const std::string& className,
                                       const std::string& method, uint64_t a1,
                                       uint64_t a2, uint64_t a3, int timeoutMs) {
    RemoteCallResult res;
    if (timeoutMs < 0) timeoutMs = defaultTimeoutMs;
    if (!inv) { res.error = "invoker kurulu degil"; return res; }
    std::string sym;
    Addr fn = resolveMethod(className, method, &sym);
    if (!fn) {
        res.error = "export bulunamadi: " + className + "::" + method +
                    " (Qt modulu sembolleri yuklu mu?)";
        return res;
    }
    if (!chainHas(objAddr, className)) {
        res.error = "nesne bu sinifin turevini degil (" + className + " bekleniyordu)";
        return res;
    }
    res = inv->callFn(fn, objAddr, a1, a2, a3, timeoutMs);
    if (res.ok)
        fprintf(stderr, "[invoke] %s::%s @0x%llx (this=0x%llx) ret=%llu %s\n",
                className.c_str(), method.c_str(), (unsigned long long)fn,
                (unsigned long long)objAddr, (unsigned long long)res.ret,
                sym.c_str());
    else if (res.pending)
        fprintf(stderr, "[invoke] %s::%s PENDING (modal?) — GUI serbest\n",
                className.c_str(), method.c_str());
    return res;
}

// ------------------------------------------------------- yuksek seviye ----
RemoteCallResult QtActor::click(Addr widget, int timeoutMs) {
    return invokeMethod(widget, "QAbstractButton", "click", 0, 0, 0, timeoutMs);
}

// --------------------------------------- V3.2 — statik-Qt slot invoke ----
// qt_static_metacall(_o, InvokeMetaMethod, _id, _a) — export tablosu olmayan
// hedeflerde (Qt'i statik gömen VMProtect.exe gibi) "Class::slot" çağrısı.
// Yarıçap: parametresiz slotlar (addFunction(), compile(), show()...).
RemoteCallResult QtActor::callSlot(Addr objAddr, const std::string& slotName, int timeoutMs,
                                   const std::string* strArg) {
    RemoteCallResult res;
    if (timeoutMs < 0) timeoutMs = defaultTimeoutMs;
    if (!inv || !proc || !reg) { res.error = "invoker/registry kurulu degil"; return res; }

    // 1) vtable -> sınıf kaydı (metacall + metot listesi)
    Addr vt = proc->readAddr(objAddr);
    if (!vt) { res.error = "vtable okunamadi"; return res; }
    const MetaClassInfo* ci = reg->resolveVtable(vt);
    if (!ci) { res.error = "sinif kaydi yok (metaobject cozumlenemedi)"; return res; }
    if (!ci->staticMetacall) { res.error = "qt_static_metacall adresi yok"; return res; }

    // 2) slot indeksini bul — isim ya da "name(" imza öneki
    int idx = -1;
    for (size_t i = 0; i < ci->methods.size(); i++) {
        const MetaMethod& m = ci->methods[i];
        if (m.name == slotName) { idx = (int)i; break; }
        if (m.signature.rfind(slotName + "(", 0) == 0) { idx = (int)i; break; }
    }
    if (idx < 0) { res.error = "slot bulunamadi: " + slotName; return res; }

    // 3) argv dizisini hedefte kur — argv[0]=retval, parametresiz slotta {0} yeterli
    Addr argv = inv->remoteAlloc(64);
    if (!argv) { res.error = "uzak argv alani ayrilamadi"; return res; }
    uint64_t zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    inv->remoteWrite(argv, zeros, sizeof(zeros));

    // 3b) V3.2 — QString argümanlı slotlar (QLineEdit::setText gibi):
    //     argv[1] = hedefte kurulan QString nesnesinin adresi
    Addr qstr = 0;
    if (strArg && !strArg->empty()) {
        std::string qerr;
        qstr = makeQString(*strArg, &qerr);
        if (!qstr) { res.error = "QString kurulamadi: " + qerr; return res; }
        uint64_t arg1 = (uint64_t)qstr;
        inv->remoteWrite(argv + 8, &arg1, 8);
    }

    // 4) qt_static_metacall(_o=rcx, _c=0 InvokeMetaMethod, _id=r8, _a=r9)
    //    (Linux ELF hedeflerde SysV: rdi=_o, rsi=_c, rdx=_id, rcx=_a)
    res = inv->callFn(ci->staticMetacall, objAddr, /*_c*/ 0, /*_id*/ (uint64_t)idx,
                      /*_a*/ argv, timeoutMs);
    if (res.ok)
        fprintf(stderr, "[invoke] %s::%s qt_static_metacall idx=%d (this=0x%llx) ret=%llu\n",
                ci->className.c_str(), slotName.c_str(), idx,
                (unsigned long long)objAddr, (unsigned long long)res.ret);
    else if (res.pending)
        fprintf(stderr, "[invoke] %s::%s PENDING (modal?) — GUI serbest\n",
                ci->className.c_str(), slotName.c_str());
    if (res.ok || res.pending) {
        // slot çağrıldı — dönen argv[0] retval'ini oku (basit tiplerde anlamlı)
        uint64_t rv = 0;
        if (inv->remoteRead(argv, &rv, 8)) res.ret = rv;
    }
    return res;
}

RemoteCallResult QtActor::setChecked(Addr widget, bool on, int timeoutMs) {
    return invokeMethod(widget, "QAbstractButton", "setChecked", on ? 1 : 0, 0, 0, timeoutMs);
}
RemoteCallResult QtActor::setComboIndex(Addr combo, int index, int timeoutMs) {
    return invokeMethod(combo, "QComboBox", "setCurrentIndex", (uint64_t)(int64_t)index, 0, 0, timeoutMs);
}
RemoteCallResult QtActor::selectRow(Addr listWidget, int row, int timeoutMs) {
    return invokeMethod(listWidget, "QListWidget", "setCurrentRow", (uint64_t)(int64_t)row, 0, 0, timeoutMs);
}
RemoteCallResult QtActor::setTab(Addr tabWidget, int index, int timeoutMs) {
    return invokeMethod(tabWidget, "QTabWidget", "setCurrentIndex", (uint64_t)(int64_t)index, 0, 0, timeoutMs);
}

// ---- setText: QString'i HEDEPTE kur, sonra QLineEdit::setText(QString) ----
RemoteCallResult QtActor::setText(Addr lineEdit, const std::string& utf8, int timeoutMs) {
    RemoteCallResult res;
    if (timeoutMs < 0) timeoutMs = defaultTimeoutMs;
    if (!inv) { res.error = "invoker kurulu degil"; return res; }
    std::string err;
    Addr qs = makeQString(utf8, &err);
    if (!qs) { res.error = err.empty() ? "QString kurulamadi" : err; return res; }
    return invokeMethod(lineEdit, "QLineEdit", "setText", qs, 0, 0, timeoutMs);
}

// ---------------------------------------------------------------- QString --
// Qt6: QString = QArrayDataPointer { d; ptr; size }  (24B)
//       d  -> QArrayData { ref=-1; size=n; alloc=n } + utf16 @ ptr
// Qt5: QString = { QStringData* d } (8B)
//       d  -> { ref=-1; size=n(int); alloc=n; offset=24 } + utf16 @ d+24
Addr QtActor::makeQString(const std::string& utf8, std::string* err) {
    if (!inv || !L) { if (err) *err = "invoker/layout yok"; return 0; }

    // utf8 -> utf16
    std::vector<uint16_t> w;
    {
        const unsigned char* s = (const unsigned char*)utf8.c_str();
        size_t i = 0, n = utf8.size();
        while (i < n) {
            unsigned c = s[i];
            if (c < 0x80) { w.push_back((uint16_t)c); i++; }
            else if ((c & 0xE0) == 0xC0 && i + 1 < n) {
                w.push_back((uint16_t)(((c & 0x1F) << 6) | (s[i+1] & 0x3F))); i += 2;
            } else if ((c & 0xF0) == 0xE0 && i + 2 < n) {
                w.push_back((uint16_t)(((c & 0x0F) << 12) | ((s[i+1] & 0x3F) << 6) | (s[i+2] & 0x3F))); i += 3;
            } else if ((c & 0xF8) == 0xF0 && i + 3 < n) {
                uint32_t cp = ((c & 0x07) << 18) | ((s[i+1] & 0x3F) << 12) |
                              ((s[i+2] & 0x3F) << 6) | (s[i+3] & 0x3F);
                cp -= 0x10000;
                w.push_back((uint16_t)(0xD800 + (cp >> 10)));
                w.push_back((uint16_t)(0xDC00 + (cp & 0x3FF)));
                i += 4;
            } else { w.push_back((uint16_t)'?'); i++; }
        }
    }
    size_t n = w.size();
    if (n > 0x100000) { if (err) *err = "yazi cok uzun"; return 0; }

    if (L->qt6Layout) {
        // ---- Qt6 ----
        // ayirma: [QArrayData 24B][utf16 pad-to-4]  + QString objesi [d][ptr][size]
        size_t total = 24 + ((n * 2 + 3) & ~3UL) + 0x10;
        Addr block = inv->remoteAlloc(total + 64);
        if (!block) { if (err) *err = "uzak bellek ayrlamadi"; return 0; }
        Addr header = block;
        Addr data   = block + 24;
        Addr obj    = block + 24 + ((n * 2 + 3) & ~3UL) + 8;   // 8 hizali
        // header: ref(4)=1 (PAYLASILABILIR — hedef kopyasi paylaşir,
        // kimse free etmez; ref=-1 statik Qt6'da free yolunu açiyordu)
        unsigned char h[24] = {};
        int32_t ref = 1;
        memcpy(h + 0, &ref, 4);
        int64_t sz = (int64_t)n;
        memcpy(h + 8, &sz, 8);
        uint32_t allocv = (uint32_t)n;
        memcpy(h + 16, &allocv, 4);
        if (!inv->remoteWrite(header, h, 24) ||
            (n && !inv->remoteWrite(data, w.data(), n * 2))) {
            if (err) *err = "QString verisi yazilamadi";
            return 0;
        }
        // QString nesnesi: [d][ptr][size]
        uint64_t qobj[3] = { (uint64_t)header, (uint64_t)data, (uint64_t)n };
        if (!inv->remoteWrite(obj, qobj, 24)) { if (err) *err = "QString objesi yazilamadi"; return 0; }
        return obj;
    } else {
        // ---- Qt5 ----
        // ayirma: [QArrayData 24B][utf16] + QString objesi [d]
        size_t total = 24 + n * 2;
        Addr block = inv->remoteAlloc(total + 64);
        if (!block) { if (err) *err = "uzak bellek ayrlamadi"; return 0; }
        Addr header = block;
        // { ref(0)=1 (paylasilabilir); size(4)=n; alloc(8)=n; offset(16)=24 }
        unsigned char h[24] = {};
        int32_t ref = 1, sz = (int32_t)n, allocv = (int32_t)n;
        memcpy(h + 0, &ref, 4);
        memcpy(h + 4, &sz, 4);
        memcpy(h + 8, &allocv, 4);
        int64_t off = 24;
        memcpy(h + 16, &off, 8);
        if (!inv->remoteWrite(header, h, 24) ||
            (n && !inv->remoteWrite(header + 24, w.data(), n * 2))) {
            if (err) *err = "QString verisi yazilamadi";
            return 0;
        }
        uint64_t d = (uint64_t)header;
        Addr obj = header + 24 + ((n * 2 + 7) & ~7UL) + 8;
        if (!inv->remoteWrite(obj, &d, 8)) { if (err) *err = "QString objesi yazilamadi"; return 0; }
        return obj;
    }
}

} // namespace umvpqt
