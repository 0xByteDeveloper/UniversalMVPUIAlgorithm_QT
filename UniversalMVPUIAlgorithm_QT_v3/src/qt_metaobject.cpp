// UMVPQT GOD STATE — QMetaObject Parser implementation
// ============================================================================
//  GOD derinlik: bellekteki QMetaObject'in stringdata/data dizilerini eraya
//  gore cozer. Qt5 (QByteArrayData tablosu), Qt6 (offset/length ciftleri),
//  Qt4 (char* blob) destekli. Metod isimleri -> signal/slot/event cozumleri.
// ============================================================================
#include "umvpqt/qt_metaobject.h"
#include <cstring>

namespace umvpqt {

// ------------------------------------------------------------- eralar ----
// data[0] = revision: 7=Qt5.0, 8=Qt5.12+, 9=Qt6.0, 10=Qt6.2, 11=Qt6.5, 12=Qt6.6+
static QtEra eraFromRevision(int rev) {
    if (rev >= 9) return QtEra::Qt6;
    if (rev >= 7) return QtEra::Qt5;
    if (rev >= 1) return QtEra::Qt4;
    return QtEra::Unknown;
}

// ---------------------------------------------------------- strings ------
std::string MetaObjectParser::readMetaString(Addr stringdataAddr, uint32_t index,
                                             QtEra era, int revision) {
    if (!stringdataAddr || index > 0x100000) return {};
    if (era == QtEra::Qt6) {
        // stringdata[i] = (offset uint, length uint) ciftleri
        uint32_t off = proc_.readU32(stringdataAddr + 8ull * index);
        uint32_t len = proc_.readU32(stringdataAddr + 8ull * index + 4);
        if (off == 0 || off > 0x4000000 || len == 0 || len > 0x100000) return {};
        Addr s = stringdataAddr + off;
        std::vector<char> b(len + 1);
        if (!proc_.read(s, b.data(), len)) return {};
        b[len] = 0;
        return std::string(b.data());
    } else if (era == QtEra::Qt5) {
        // QByteArrayData header tablosu: her kayit 24B (64-bit)
        // { ref(4) size(4) alloc(4) pad(4) offset(8) } — veri: header + offset
        Addr h = stringdataAddr + (Addr)(index) * 24ull;
        int32_t size = proc_.readI32(h + 4);
        if (size < 0 || size > 0x100000) return {};
        int64_t offset = (int64_t)proc_.readAddr(h + 16);
        Addr s = h + (Addr)offset;
        if (size == 0) return {};
        std::vector<char> b((size_t)size + 1);
        if (!proc_.read(s, b.data(), (size_t)size)) return {};
        b[size] = 0;
        return std::string(b.data());
    } else if (era == QtEra::Qt4) {
        // Qt4: stringdata = char* blob; offset data dizisindeki kayita bagli — nadiren gerekir
        // Qt4 data'da metod adi zaten offset olarak verilir; burada offset=index varsayiyoruz
        Addr s = stringdataAddr + (Addr)index;
        std::vector<char> b(256);
        if (!proc_.read(s, b.data(), 256)) return {};
        for (int i = 0; i < 256; i++) if (b[i] == 0) return std::string(b.data(), i);
        return {};
    }
    return {};
}

// ------------------------------------------------------- looksLike ------
bool MetaObjectParser::looksLikeMetaObject(Addr moAddr, int* revisionOut) {
    if (!moAddr || moAddr < 0x10000) return false;
    MoView v = moView(proc_, L, moAddr);
    if (!v.data || !v.stringdata) return false;
    if (!v.static_metacall && !v.superdata) return false;   // en az biri dolu olmali
    uint32_t rev = proc_.readU32(v.data);
    if (rev < 4 || rev > 20) return false;
    if (revisionOut) *revisionOut = (int)rev;
    // className index makul aralikta mi
    uint32_t cls = proc_.readU32(v.data + 4);
    if (cls > 0x10000) return false;
    return true;
}

// ------------------------------------------------------------ chain ------
bool MetaObjectParser::classChain(IProcessReader& proc, const QtLayouts& L, Addr moAddr,
                                  std::vector<Addr>& chainOut) {
    chainOut.clear();
    Addr m = moAddr;
    for (int guard = 0; m && guard < 64; guard++) {
        chainOut.push_back(m);
        MoView v = moView(proc, L, m);
        // SuperData = inline tek isaretci (direct) — ekstra deref YOK
        m = v.superdata;
    }
    return !chainOut.empty();
}

// ------------------------------------------------------------- parse -----
bool MetaObjectParser::parse(Addr moAddr, MetaClassInfo& out) {
    if (!looksLikeMetaObject(moAddr)) return false;
    MoView v = moView(proc_, L, moAddr);
    int revision = (int)proc_.readU32(v.data);
    QtEra era = eraFromRevision(revision);

    out.metaObject = moAddr;
    out.staticMetacall = v.static_metacall;
    // Qt5'te superdata SuperData yapisidir: [ptr] tek alan — dogrudan okunur

    // className
    uint32_t clsIdx = proc_.readU32(v.data + 4);
    out.className = readMetaString(v.stringdata, clsIdx, era, revision);
    if (out.className.empty() || out.className.size() > 256) return false;

    // ---- header ----
    uint32_t methodCount   = proc_.readU32(v.data + 4 * 4);
    uint32_t methodData    = proc_.readU32(v.data + 4 * 5);
    uint32_t propCount     = proc_.readU32(v.data + 4 * 6);
    uint32_t propData      = proc_.readU32(v.data + 4 * 7);
    uint32_t enumCount     = proc_.readU32(v.data + 4 * 8);
    uint32_t enumData      = proc_.readU32(v.data + 4 * 9);
    uint32_t ctorCount     = proc_.readU32(v.data + 4 * 10);
    uint32_t ctorData      = proc_.readU32(v.data + 4 * 11);
    uint32_t flags        = proc_.readU32(v.data + 4 * 12);
    uint32_t signalCount  = proc_.readU32(v.data + 4 * 13);

    (void)enumCount; (void)enumData; (void)ctorCount; (void)ctorData; (void)flags;
    out.signalCount = (int)signalCount;
    if (methodCount > 512 || propCount > 512) return false;   // saldiri sigortasi

    unsigned intsPerMethod = L.mo_IntsPerMethod;
    unsigned intsPerProp  = L.mo_IntsPerProperty;

    // ---- methodlar ----
    for (uint32_t i = 0; i < methodCount; i++) {
        Addr e = v.data + (Addr)(methodData + i * intsPerMethod) * 4ull;
        uint32_t nameIdx = proc_.readU32(e);
        uint32_t argc    = proc_.readU32(e + 4);
        uint32_t parIdx  = proc_.readU32(e + 8);
        uint32_t tagIdx  = proc_.readU32(e + 12);
        uint32_t mflags  = proc_.readU32(e + 16);
        (void)parIdx; (void)tagIdx;
        MetaMethod mm;
        mm.name = readMetaString(v.stringdata, nameIdx, era, revision);
        mm.flags = mflags;
        mm.parameterCount = (int)argc;
        mm.isSignal = (mflags & 0x0c) == 0x04;
        mm.isSlot   = (mflags & 0x0c) == 0x08;
        // imza: adi + parametre tipleri
        if (!mm.name.empty()) {
            mm.signature = mm.name + "(";
            // parametreler: metod parameters dizisinde: tipler (argc+1) + isimler (argc)
            // basit imza: sadece isim — tip listesi disasm analizinde zenginlestirilir
            mm.signature += ")";
        }
        out.methods.push_back(mm);
    }

    // ---- property'ler ----
    for (uint32_t i = 0; i < propCount; i++) {
        Addr e = v.data + (Addr)(propData + i * intsPerProp) * 4ull;
        uint32_t nameIdx = proc_.readU32(e);
        uint32_t typeVal = proc_.readU32(e + 4);      // Qt6: metatype id; Qt5: id
        uint32_t pflags  = proc_.readU32(e + 8);
        MetaProperty mp;
        mp.name = readMetaString(v.stringdata, nameIdx, era, revision);
        mp.flags = pflags;
        mp.readable = pflags & 0x01;
        mp.writable = pflags & 0x02;
        mp.type = typeVal <= 0x7FF ? "builtin#" + std::to_string(typeVal) : "?";
        out.properties.push_back(mp);
    }

    // ---- superdata zinciri ----
    std::vector<Addr> chain;
    if (classChain(proc_, L, moAddr, chain)) {
        for (size_t i = 1; i < chain.size(); i++) {   // [0] = kendisi
            Addr sm = chain[i];
            MoView sv = moView(proc_, L, sm);
            uint32_t cidx = proc_.readU32(sv.data + 4);
            std::string sn = readMetaString(sv.stringdata, cidx, era, revision);
            if (!sn.empty()) out.superChain.push_back(sn);
        }
    }
    return true;
}

int MetaObjectParser::absoluteMethodIndex(Addr moAddr, int relativeIndex) {
    // global method index = parent methodCount toplamlari + relative
    int acc = 0;
    std::vector<Addr> chain;
    classChain(proc_, L, moAddr, chain);
    for (size_t i = 1; i < chain.size(); i++) {
        MoView v = moView(proc_, L, chain[i]);
        acc += (int)proc_.readU32(v.data + 4 * 4);
    }
    return acc + relativeIndex;
}

} // namespace umvpqt
