// UMVPQT GOD STATE — Detection + Instance Scan + Class Registry (impl)
// ============================================================================
//  GOD invaryant: her QObject icin *(obj + ptr) = d ve *(d + 8*ptrW) = obj.
//  Vtable'dan sinif: (1) Qt sembol vtable tablosu, (2) metaObject thunk.
// ============================================================================
#include "umvpqt/qt_scan.h"
#include <cstring>
#include <algorithm>
#include <capstone/capstone.h>

namespace umvpqt {


// Intel CET on eki endbr64 (F3 0F 1E FA) ve nop paddingsini atla
static int skipPrefix(const uint8_t* code, int len) {
    int off = 0;
    while (off + 4 <= len && code[off] == 0xF3 && code[off+1] == 0x0F && code[off+2] == 0x1E && code[off+3] == 0xFA)
        off += 4;   // endbr64
    while (off + 1 <= len && code[off] == 0x90) off += 1;   // nop
    return off;
}

// ================================================================ tespit ==
// V307-3: bellekte alt-dizi ara (memmem yerine taşınabilir yardımcı)
static const void* findSub(const void* hay, size_t hayLen, const void* nd, size_t ndLen) {
    if (ndLen == 0 || hayLen < ndLen) return nullptr;
    const uint8_t* h = (const uint8_t*)hay;
    const uint8_t* n = (const uint8_t*)nd;
    for (size_t i = 0; i + ndLen <= hayLen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, ndLen) == 0) return h + i;
    }
    return nullptr;
}

std::string QtDetector::versionViaQVersion(IProcessReader& proc, ModuleTable& mt) {
    Addr fn = mt.qVersionFn();
    if (!fn) return {};
    // qVersion(): "[endbr64] lea/mov rax,[rip+disp]; ret"
    uint8_t code[32] = {};
    if (!proc.read(fn, code, 32)) return {};
    int pre = skipPrefix(code, 32);
    const uint8_t* c = code + pre;
    if (proc.ptrSize() == 8 && ((c[0] == 0x48 && (c[1] == 0x8B || c[1] == 0x8D) && c[2] == 0x05 && c[7] == 0xC3))) {
        int32_t disp = (int32_t)(c[3] | c[4] << 8 | c[5] << 16 | (uint32_t)c[6] << 24);
        Addr str = fn + pre + 7 + disp;
        char buf[32] = {};
        if (proc.read(str, buf, 16)) {
            for (int i = 0; i < 16; i++) if (buf[i] == 0) { return std::string(buf, i); }
        }
    } else if (proc.ptrSize() == 4 && c[0] == 0xB8 && c[5] == 0xC3) {
        uint32_t str = c[1] | c[2] << 8 | c[3] << 16 | c[4] << 24;
        char buf[32] = {};
        if (proc.read(str, buf, 16)) {
            for (int i = 0; i < 16; i++) if (buf[i] == 0) { return std::string(buf, i); }
        }
    }
    return {};
}

std::string QtDetector::versionViaScan(IProcessReader& proc, const Module& core) {
    // Qt core rodata icinde "N.N.N" ara (qVersion stringi kopyasi)
    for (auto& r : proc.regions()) {
        if (r.path != core.path) continue;
        if (!r.read) continue;
        // sadece rodata benzeri (yazilamaz) bolgeler + data bolgeleri
        if (r.write && !r.exec) continue;   // heap degil
        size_t sz = (size_t)(r.end - r.start);
        if (sz > 64ull * 1024 * 1024) continue;
        std::vector<char> buf(sz);
        if (!proc.read(r.start, buf.data(), sz)) continue;
        for (size_t i = 0; i + 16 < sz; i++) {
            if ((buf[i] == '4' || buf[i] == '5' || buf[i] == '6') && buf[i + 1] == '.' &&
                buf[i + 2] >= '0' && buf[i + 2] <= '9' && buf[i + 3] == '.' &&
                buf[i + 4] >= '0' && buf[i + 4] <= '9') {
                std::string s(buf.data() + i, 8);
                // sonrakini kes (NUL)
                size_t z = s.find_first_not_of("0123456789.");
                if (z != std::string::npos) s = s.substr(0, z);
                if (s.size() >= 5) return s;
            }
        }
    }
    return {};
}

bool QtDetector::detect(IProcessReader& proc, ModuleTable& mt, const QtLayouts& L, QtInfo& out) {
    // ---- 1) modul isimlerinden cag ----
    const Module* core = nullptr;
    for (auto& m : mt.modules()) {
        std::string n = m.name;
        bool isCore = n.find("Qt6Core") != std::string::npos || n.find("Qt5Core") != std::string::npos
                   || n == "QtCore.dll" || n.find("libQt6Core") != std::string::npos
                   || n.find("libQt5Core") != std::string::npos;
        if (isCore) { core = &m; break; }
    }
    if (!core) {
        // fallback: herhangi Qt modulu?
        for (auto& m : mt.modules()) {
            if (m.name.find("Qt6") != std::string::npos || m.name.find("Qt5") != std::string::npos ||
                m.name.find("Qt") == 0) { core = &m; break; }
        }
        if (!core) {
            // ============================================================
            // V307-3 YAMASI — STATİK-Qt TESPİTİ (bellek imza fallback'i)
            // ------------------------------------------------------------
            // Sorun (V302): VMProtect gibi statik bağlanmış self-protected
            // ikili dosyalar HİÇBİR Qt DLL modülü yüklemez. Bu noktada klasik
            // yol 'Qt yok' deyip analyze'i durduruyordu → 0 form / 0 obje.
            // Çözüm: modül bulunamadıysa okunabilir bellek bölgelerinde Qt
            // imzalarını ara:
            //   UTF-8  : "qt_meta_stringdata" / "QMainWindow" / "lsFile"
            //            (moc motoru + pencere sınıfı + VMProtect'ın kendi
            //             çeviri anahtarı)
            //   UTF-16 : "File" / "Edit" / "View" (Qt menü metinleri)
            // Motor imzası VE UI metni birlikte bulunursa → "Qt5 (static)"
            // ile devam: nesne taraması invariant (q_ptr geri-bağı) yoluyla
            // DLL'e ihtiyaç duymadan çalışır. metaobject verisi şifreli
            // olsa bile sınıf kaydı kısmi kalır, tespit kesinleşir.
            // ============================================================
            int u8 = 0, u16 = 0;
            static const char* kUtf8[]  = { "qt_meta_stringdata", "QMainWindow", "lsFile" };
            static const char* kUtf16[] = { "File", "Edit", "View" };
            for (auto& r : proc.regions()) {
                if (!r.read) continue;
                if (r.exec) continue;                        // sadece data/rodata/heap
                Addr sz = r.end - r.start;
                if (sz > 64ull * 1024 * 1024) continue;      // hız sınırı: 64MB üstü atla
                std::vector<char> buf((size_t)sz);
                if (!proc.read(r.start, buf.data(), buf.size())) continue;
                for (const char* s : kUtf8)
                    if (findSub(buf.data(), buf.size(), s, strlen(s))) u8++;
                for (const char* s : kUtf16) {
                    // UTF-16LE: "File" -> 'F',0,'i',0,'l',0,'e',0
                    std::string w;
                    for (const char* p = s; *p; p++) { w.push_back(*p); w.push_back('\0'); }
                    if (findSub(buf.data(), buf.size(), w.data(), w.size())) u16++;
                }
            }
            if (u8 > 0 && u16 > 0) {
                // hem moc motor imzası hem UI metni → güvenli teşhis
                out.present = true;
                out.era = QtEra::Qt5;
                out.detection = "memory-signature: Qt5 (static) — V307-3";
                out.coreModule.clear();
                return true;
            }
            return false;   // Qt gerçekten yok
        }
    }
    out.present = true;
    out.coreModule = core->path;
    std::string n = core->name;
    out.era = (n.find('6') != std::string::npos || n.find("Qt6") != std::string::npos) ? QtEra::Qt6 : QtEra::Qt5;
    // Qt4: qtcore.dll / libQtCore.so.4
    if (n.find("QtCore") != std::string::npos && n.find("Qt") == 0 && n.find('4') != std::string::npos)
        out.era = QtEra::Qt4;
    out.detection = "module: " + n;

    // ---- 2) tam surum: qVersion disassembly ----
    std::string v = versionViaQVersion(proc, mt);
    if (v.empty()) v = versionViaScan(proc, *core);
    out.version = v;
    if (!v.empty()) {
        // surumden cag tashi (Qt5 / Qt6)
        if (v[0] == '6') out.era = QtEra::Qt6;
        else if (v[0] == '5') out.era = QtEra::Qt5;
        else if (v[0] == '4') out.era = QtEra::Qt4;
    }

    // ---- 3) widgets modulu ----
    for (auto& m : mt.modules()) {
        if (m.name.find("Widgets") != std::string::npos) { out.widgetsModule = m.path; break; }
    }
    return true;
}

// ================================================== vtable thunk cozumu ==
// metaObject() override'u (moc 6.x): d_ptr->metaObject ? dynamicMetaObject : &staticMetaObject
// => thunk DALLI kod icerir. Capstone ile rip-gorelili hedefleri tara,
//    looksLikeMetaObject gecen ilk hedefi al (GOD: ampirik dogrulama).
static bool quickLooksLikeMo(IProcessReader& proc, Addr mo) {
    if (!mo || mo < 0x10000) return false;
    Addr stringdata = proc.readAddr(mo + 8);
    Addr data      = proc.readAddr(mo + 16);
    Addr metacall  = proc.readAddr(mo + 24);
    if (!stringdata || !data) return false;
    uint32_t rev = proc.readU32(data);
    if (rev < 4 || rev > 20) return false;
    uint32_t cls = proc.readU32(data + 4);
    if (cls > 0x10000) return false;
    // stringdata'dan className okunabilir mi? (era bagimsiz hizli kontrol)
    return true;
}

static Addr capstoneFindMetaObjectInThunk(IProcessReader& proc, Addr slot0) {
    uint8_t code[192] = {};
    if (!proc.read(slot0, code, sizeof(code))) return 0;
    csh cs;
    if (cs_open(CS_ARCH_X86, proc.ptrSize() == 8 ? CS_MODE_64 : CS_MODE_32, &cs) != CS_ERR_OK)
        return 0;
    cs_insn* insns = nullptr;
    size_t n = cs_disasm(cs, code, sizeof(code), (uint64_t)slot0, 96, &insns);
    Addr best = 0;
    if (n && insns) {
        for (size_t i = 0; i < n; i++) {
            const char* op = insns[i].op_str;
            // her rip-gorelili hedefi dene: "rax, [rip + 0x..]" tarzi
            if (strstr(op, "rip")) {
                const char* rp = strstr(op, "rip");
                const char* plus = strchr(rp, '+');
                const char* minus = strchr(rp, '-');
                const char* use = plus ? plus : minus;
                int sign = plus ? 1 : -1;
                if (use) {
                    long long disp = sign * strtoll(use + 1, nullptr, 16);
                    Addr target = insns[i].address + insns[i].size + disp;
                    if (quickLooksLikeMo(proc, target)) { best = target; break; }
                }
            }
        }
        cs_free(insns, n);
    }
    cs_close(&cs);
    return best;
}

Addr resolveMetaObjectFromVtable(IProcessReader& proc, Addr vtable, bool* ok) {
    // vtable: isaretci dizisi; slot0 (offset-to-top ve RTTI'dan sonra) = metaObject()
    // Itanium: vtable_ptr adresi zaten ilk sanal fonksiyonu gosterir
    Addr slot0 = proc.readAddr(vtable);
    if (!slot0 || slot0 < 0x1000) { if (ok) *ok = false; return 0; }
    uint8_t code[32] = {};
    if (!proc.read(slot0, code, 32)) { if (ok) *ok = false; return 0; }
    int pre = skipPrefix(code, 32);
    const uint8_t* c = code + pre;
    if (proc.ptrSize() == 8) {
        // MOV rax,[rip+disp]; ret — dolayli (superdata-style)
        if (c[0] == 0x48 && c[1] == 0x8B && c[2] == 0x05 && c[7] == 0xC3) {
            int32_t disp = (int32_t)(c[3] | c[4] << 8 | c[5] << 16 | (uint32_t)c[6] << 24);
            if (ok) *ok = true;
            return slot0 + pre + 7 + disp;
        }
        // LEA rax,[rip+disp]; ret — dogrudan staticMetaObject
        if (c[0] == 0x48 && c[1] == 0x8D && c[2] == 0x05 && c[7] == 0xC3) {
            int32_t disp = (int32_t)(c[3] | c[4] << 8 | c[5] << 16 | (uint32_t)c[6] << 24);
            if (ok) *ok = true;
            return slot0 + pre + 7 + disp;
        }
        // DALLI thunk (moc 6.x override): capstone ile rip-gorelili metaobject ara
        Addr mo = capstoneFindMetaObjectInThunk(proc, slot0);
        if (mo) { if (ok) *ok = true; return mo; }
    } else {
        if (c[0] == 0xB8 && c[5] == 0xC3) {   // mov eax, imm32; ret
            uint32_t v = c[1] | c[2] << 8 | c[3] << 16 | c[4] << 24;
            if (ok) *ok = true;
            return v;
        }
    }
    if (ok) *ok = false;
    return 0;
}

// ====================================================== ClassRegistry ==
std::string demangleItanium(const char* name) {
    // basit Itanium demangler: "12MyWidget" / "N3Foo3BarE" tarzi
    std::string out;
    const char* p = name;
    bool nested = false;
    if (*p == 'N') { nested = true; p++; }
    while (*p && *p != 'E') {
        char* end = nullptr;
        long len = strtol(p, &end, 10);
        if (len <= 0 || !end) break;
        if (!out.empty()) out += "::";
        out.append(end, (size_t)len);
        p = end + len;
    }
    if (nested && *p != 'E') return {};   // bozuk
    return out;
}

std::string ClassRegistry::classNameViaRtti(Addr vtable) {
    // Itanium: vtable[-1] (vtable_ptr - P) = typeinfo*; typeinfo { vptr, name* }
    int P = proc->ptrSize();
    Addr ti = proc->readAddr(vtable - P);
    if (!ti || ti < 0x10000) return {};
    Addr namePtr = proc->readAddr(ti + P);
    if (!namePtr || namePtr < 0x1000) return {};
    char nm[128] = {};
    if (!proc->read(namePtr, nm, 127)) return {};
    nm[127] = 0;
    std::string d = demangleItanium(nm);
    return d;
}

const MetaClassInfo* ClassRegistry::resolveVtable(Addr vtable) {
    if (!vtable) return nullptr;
    auto it = byVtable.find(vtable);
    if (it != byVtable.end()) return &it->second;

    MetaClassInfo ci;
    bool resolved = false;

    // ---- yol 1: Qt modul sembolleri (vtable for X) ----
    // Vtable isaretcisi sembolden +0x10 kaydirilir (Itanium: ofset/RTTI oncesi)
    // Sembol adresi zaten vtable basi; bellekte vtable_ptr = vtable_sym + 2*ptrW
    if (mt) {
        Addr vtableSym = vtable - (Addr)(2 * proc->ptrSize());
        const Symbol* s = nullptr;
        for (auto& m : mt->modules()) {
            for (auto& sy : m.symbols) {
                if (sy.address == vtableSym) { s = &sy; break; }
            }
            if (s) break;
        }
        if (s) {
            std::string cls;
            if (itaniumVtableClassName(s->name, cls) || msvcVtableClassName(s->name, cls)) {
                ci.className = cls;
                // staticMetaObject sembolden
                std::string modOut;
                Addr mo = mt->staticMetaObjectOf(cls, &modOut);
                ci.metaObject = mo;
                if (mo) {
                    moParser->parse(mo, ci);
                    resolved = true;
                } else {
                    resolved = true;  // sinif adi yeterli (Q_OBJECT'suz Qt sinifi?)
                }
            }
        }
    }

    // ---- yol 2: metaObject thunk -> QMetaObject ----
    if (!resolved) {
        bool ok = false;
        Addr mo = resolveMetaObjectFromVtable(*proc, vtable, &ok);
        if (ok && mo) {
            ci.metaObject = mo;
            if (moParser->parse(mo, ci)) resolved = true;
        }
    }

    // ---- yol 3: RTTI ile gercek app sinif adi (Q_OBJECT'suz turetmeler) ----
    if (resolved || !resolved) {
        std::string rtti = classNameViaRtti(vtable);
        if (!rtti.empty() && rtti != ci.className && rtti != "QObject") {
            // metaobject tabanli ad Qt taban sinifi olabilir; RTTI daha spesifik
            ci.classNameResolved = rtti;
            if (ci.className.empty()) { ci.className = rtti; resolved = true; }
        }
    }
    if (!resolved) return nullptr;
    auto [pos, inserted] = byVtable.emplace(vtable, std::move(ci));
    return inserted ? &pos->second : nullptr;
}

const MetaClassInfo* ClassRegistry::resolveMetaObject(Addr mo) {
    if (!mo) return nullptr;
    auto it = byMetaObject.find(mo);
    if (it != byMetaObject.end()) return &it->second;
    MetaClassInfo ci;
    if (!moParser->parse(mo, ci)) return nullptr;
    auto [pos, inserted] = byMetaObject.emplace(mo, std::move(ci));
    return inserted ? &pos->second : nullptr;
}

bool ClassRegistry::chainContains(const MetaClassInfo& ci, const std::string& cls) const {
    if (ci.className == cls) return true;
    for (auto& s : ci.superChain) if (s == cls) return true;
    return false;
}
bool ClassRegistry::isWidgetClass(const MetaClassInfo& ci) const {
    if (qwidgetStaticMetaObject && ci.metaObject == qwidgetStaticMetaObject) return true;
    return chainContains(ci, "QWidget");
}

// ================================================== InstanceScan ========
bool InstanceScan::isValidQObject(IProcessReader& proc, const QtLayouts& L, Addr x,
                                  Addr* dOut, Addr* vtableOut) {
    int P = proc.ptrSize();
    Addr vtable = proc.readAddr(x);
    if (vtable < 0x10000) return false;
    Addr d = proc.readAddr(x + P);
    if (d < 0x10000) return false;
    // d'de: [vptr][q_ptr] — q_ptr = x olmali
    Addr back = proc.readAddr(d + P);   // QObjectData.q_ptr — hizaya gore P ofseti
    if (back != x) return false;
    // vtable gecerli modul araliginda mi? (heap'te din. metaobject olabilir — gevsek)
    if (dOut) *dOut = d;
    if (vtableOut) *vtableOut = vtable;
    return true;
}

std::vector<Addr> InstanceScan::scanQObjects(IProcessReader& proc, const QtLayouts& L,
                                            const ModuleTable& mt,
                                            size_t maxBytesPerRegion) {
    std::vector<Addr> out;
    int P = proc.ptrSize();
    auto regions = proc.regions();
    // on-filtre: yazilabilir-anonim bolgeler (heap) + yigin
    size_t scannedRegions = 0, scannedBytes = 0, candChecked = 0, candDPass = 0, validHit = 0;
    // ---- GOD vtable-anchored tarama: bilinen vtable degerlerini (semoller) ara ----
    std::vector<Addr> knownVts;
    for (auto& m : mt.modules()) {
        for (auto& s : m.symbols) {
            std::string cls;
            if (itaniumVtableClassName(s.name, cls)) {
                Addr vp = s.address + 2 * P;
                knownVts.push_back(vp);
            }
        }
    }
    std::sort(knownVts.begin(), knownVts.end());
    knownVts.erase(std::unique(knownVts.begin(), knownVts.end()), knownVts.end());
    size_t vtAnchored = 0;
    std::vector<Addr> anchoredOut;
    Addr qwidgetVt = mt.vtableOf("QWidget");
    for (auto& r : regions) {
        if (!r.read || !r.write) continue;
        if (!r.path.empty() && r.path[0] == '/') continue;   // dosya eslemmeli degil
        Addr sz = r.end - r.start;
        if (sz > maxBytesPerRegion) continue;
        scannedRegions++;
        scannedBytes += sz;
        std::vector<uint8_t> blob((size_t)sz);
        if (!proc.read(r.start, blob.data(), blob.size())) {
            continue;
        }
        // KESIN TESHIS: blob'u diske dok
        {
            char fn[64];
            snprintf(fn, sizeof(fn), "/tmp/umvp_dump_%llx.bin", (unsigned long long)r.start);
            FILE* df = fopen(fn, "wb");
            if (df) { fwrite(blob.data(), 1, blob.size(), df); fclose(df); }
        }
        // MANUAL TEST: QWidget needle'i dogrudan ara
        {
            Addr needle = qwidgetVt + 2 * P;
            uint64_t n8 = needle;
            const uint8_t* np = (const uint8_t*)&n8;
            bool found = false;
            for (Addr x = 0; x + 8 <= sz; x++) {
                if (blob.data()[x] == np[0]) {
                    if (memcmp(blob.data() + x, np, 8) == 0) {
                        found = true;
                        break;
                    }
                }
            }
        }
        // needle'lar: 8 bayt little-endian vtable isaretcileri
        for (Addr x = 0; x + 8 <= sz; x += 8) {
            uint64_t v = *(uint64_t*)(blob.data() + x);
            if (std::binary_search(knownVts.begin(), knownVts.end(), v)) {
                Addr obj = r.start + x;
                if (isValidQObject(proc, L, obj)) {
                    vtAnchored++;
                    anchoredOut.push_back(obj);
                }
            }
        }
    }
    for (auto& r : regions) {
        if (!r.read || !r.write) continue;
        if (!r.path.empty() && r.path[0] == '/') continue;   // dosya eslemmeli degil
        Addr sz = r.end - r.start;
        if (sz > maxBytesPerRegion) continue;
        scannedRegions++;
        scannedBytes += sz;
        // hizalali tara
        for (Addr x = (r.start + 7) & ~(Addr)7; x + 2 * P <= r.end; x += 8) {
            // hizli eleme: aday d (ikinci kelime) heap icinde olmali
            uint64_t d = 0;
            if (!proc.read(x + P, &d, P)) break;   // bolge okunamiyorsa dur
            candChecked++;
            if (d < 0x10000) {
                continue;
            }
            // d'nin bolgesi: herhangi bir RW bolge olabilir — global region tablosuna bak
            bool dInAny = false;
            for (auto& rr : regions) {
                if (!rr.read) continue;
                if (d >= rr.start && d < rr.end) { dInAny = true; break; }
            }
            if (!dInAny) continue;
            candDPass++;
            if (isValidQObject(proc, L, x)) { validHit++; out.push_back(x); }
        }
    }
    // GOD birlestirme: vtable-anchored + invariant taramalarin birlesimi (dedup)
    out.insert(out.end(), anchoredOut.begin(), anchoredOut.end());
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

} // namespace umvpqt
