// UMVPQT GOD STATE — Connection Walker implementation
// ============================================================================
//  SignalVector[0] = "allsignals" (index -1); gercek sinyaller 1..N.
//  ConnectionList = { first, last } — zincir: nextConnectionList ile ilerlenir.
// ============================================================================
#include "umvpqt/qt_connections.h"
#include <cstring>

namespace umvpqt {

std::vector<ConnectionInfo> ConnectionWalker::outgoing(Addr objAddr, int signalCountHint) {
    std::vector<ConnectionInfo> out;
    int P = proc_.ptrSize();
    // d-ptr
    Addr d = proc_.readAddr(objAddr + P);
    if (!d) return out;
    Addr cd = proc_.readAddr(d + L_.connections);          // ConnectionData*
    if (!cd || cd < 0x10000) return out;
    Addr sv = proc_.readAddr(cd + L_.cd_signalVector);     // SignalVector* (atomic, tag'li olabilir)
    if (!sv || sv < 0x10000) return out;
    if (sv & 1) sv &= ~(Addr)1;                             // TaggedSignalVector bit'i

    uint64_t allocated = proc_.readAddr(sv + L_.sv_allocated);
    if (allocated > 8192) allocated = 512;                  // saldiri sigortasi
    if (signalCountHint > 0 && (uint64_t)signalCountHint < allocated) allocated = signalCountHint + 2;

    Addr lists = sv + L_.sv_lists;                           // ConnectionList dizisi
    // [0] = allsignals (signal_index -1) — GERCEK sinyaller 1..N'den baslar
    for (uint64_t sig = 1; sig <= allocated; sig++) {
        Addr list = lists + (Addr)(sig * L_.sz_ConnectionList);
        Addr c = proc_.readAddr(list);                       // first
        int guard = 0;
        while (c && c > 0x10000 && guard++ < 256) {
            ConnectionInfo ci;
            ci.connection = c;
            Addr prevPtr = proc_.readAddr(c + L_.cn_prev);
            (void)prevPtr;
            ci.sender   = proc_.readAddr(c + L_.cn_sender);
            ci.receiver = proc_.readAddr(c + L_.cn_receiver);
            ci.callFunction = proc_.readAddr(c + L_.cn_callFunction);
            uint32_t bits = proc_.readU32(c + L_.cn_bits);
            // Qt5: [sig:27][connType:3][isSlot:1][own:1] — Qt6: [sig:27][connType:2][isSlot:1]...
            ci.isSlotObject = L_.connType_3bit ? (bits >> 30) & 1 : (bits >> 29) & 1;
            ci.signalIndex = (int)(bits & 0x07FFFFFF);
            uint16_t moff = proc_.readU16(c + L_.cn_method_offset);
            uint16_t mrel = proc_.readU16(c + L_.cn_method_relative);
            ci.slotMethodIndex = (int)moff + (int)mrel;
            // isimlendirme
            if (ci.sender == objAddr && ci.signalIndex >= 0) {
                describe(ci);
                out.push_back(ci);
            }
            // siradaki baglanti (ayni sinyal listesi)
            c = proc_.readAddr(c + L_.cn_nextConnectionList);
        }
    }
    return out;
}

void ConnectionWalker::describe(ConnectionInfo& ci) {
    // ---- yardimci: zincir uzerinde global metot/sinyal indexini coz ----
    auto resolveGlobalIndex = [&](Addr startMo, int globalIdx, bool signalsOnly, std::string& outName) -> bool {
        std::vector<Addr> chain;
        if (!MetaObjectParser::classChain(proc_, L_, startMo, chain)) return false;
        int idx = globalIdx;
        // global index uzayi: TABAN sinifin sinyalleri/metotlari ONCE gelir
        // (QObject 0..N, sonra ata... sonra self) — zinciri TERSTEN yurut:
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            Addr mo = *it;   // QObject -> ... -> self
            MoView v = moView(proc_, L_, mo);
            uint32_t rev = proc_.readU32(v.data);
            QtEra era = rev >= 9 ? QtEra::Qt6 : rev >= 7 ? QtEra::Qt5 : QtEra::Qt4;
            uint32_t methodCount = proc_.readU32(v.data + 4 * 4);
            uint32_t methodData   = proc_.readU32(v.data + 4 * 5);
            uint32_t signalCount  = proc_.readU32(v.data + 4 * 13);
            uint32_t limit = signalsOnly ? signalCount : methodCount;
            if (idx < (int)limit) {
                // metod adi: methodData + idx*IntsPerMethod -> nameIdx
                Addr e = v.data + (Addr)(methodData + idx * L_.mo_IntsPerMethod) * 4ull;
                uint32_t nameIdx = proc_.readU32(e);
                MetaObjectParser mp(proc_, L_, *reg_.mt);
                std::string nm = mp.readMetaString(v.stringdata, nameIdx, era, (int)rev);
                // imza: argc'ten "()" uretilebilir; adi yeter
                outName = nm;
                return !nm.empty();
            }
            idx -= (int)limit;
        }
        return false;
    };

    // ---- SINYAL adi: sender'in metaobject zinciri (global signal index) ----
    if (ci.sender) {
        Addr vt = proc_.readAddr(ci.sender);
        if (const MetaClassInfo* mci = reg_.resolveVtable(vt)) {
            if (mci->metaObject) {
                std::string nm;
                if (resolveGlobalIndex(mci->metaObject, ci.signalIndex, true, nm)) {
                    ci.signalName = nm;
                    ci.signalSignature = nm + "()";
                }
            }
        }
    }
    // ---- SLOT adi: receiver'in metaobject zinciri (global method index) ----
    if (ci.receiver && ci.slotMethodIndex >= 0 && !ci.isSlotObject) {
        Addr vt = proc_.readAddr(ci.receiver);
        if (const MetaClassInfo* rci = reg_.resolveVtable(vt)) {
            if (rci->metaObject) {
                std::string nm;
                if (resolveGlobalIndex(rci->metaObject, ci.slotMethodIndex, false, nm)) {
                    ci.slotSignature = rci->className + "::" + nm + "()";
                }
            }
        }
    }
    // PMF baglantisi (isSlotObject): QPrivateSlotObject icindeki PMF'den
    // slot fonksiyon ADRESINI cikar (Itanium: non-virtual PMF = {funcptr, adj})
    if (ci.isSlotObject && ci.slotCode == 0) {
        Addr slotObj = proc_.readAddr(ci.connection + L_.cn_callFunction);
        if (slotObj && slotObj > 0x10000) {
            // QSlotObjectBase { QAtomicInt m_ref(4); pad; impl fn* (8) } + Func (PMF 16B)
            Addr pmfFunc = proc_.readAddr(slotObj + 16);
            if (pmfFunc > 0x10000 && !(pmfFunc & 1)) {
                ci.slotCode = pmfFunc;
                // metacall cozum tablolarindan ismini bul
                if (Addr rvt = proc_.readAddr(ci.receiver)) {
                    if (const MetaClassInfo* rci = reg_.resolveVtable(rvt)) {
                        for (auto& [idx, addr] : rci->methodCode) {
                            if (addr == pmfFunc && idx < (int)rci->methods.size()) {
                                ci.slotSignature = rci->className + "::" + rci->methods[idx].signature;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    // baglanti tipi
    uint32_t bits = proc_.readU32(ci.connection + L_.cn_bits);
    uint32_t ctype = (bits >> 27) & (L_.connType_3bit ? 7 : 3);
    ci.connectionType = ctype == 0 ? "auto" : ctype == 1 ? "direct" :
                        ctype == 2 ? "queued" : "blocking";
}

std::vector<ConnectionInfo> ConnectionWalker::collect(const std::vector<Addr>& objects,
                                                      const std::map<Addr, MetaClassInfo>& classOf) {
    std::vector<ConnectionInfo> all;
    for (Addr o : objects) {
        int sigHint = -1;
        auto it = classOf.find(proc_.readAddr(o));
        if (it != classOf.end()) sigHint = it->second.signalCount;
        auto cs = outgoing(o, sigHint);
        for (auto& c : cs) all.push_back(c);
    }
    return all;
}

} // namespace umvpqt
