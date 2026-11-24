// UMVPQT GOD STATE — Signal/Slot Connection Walker
// ============================================================================
//  QObjectPrivate::connections -> ConnectionData -> SignalVector
//      -> ConnectionList[i] -> Connection zinciri
//  Her Connection: sender, receiver, callFunction (static_metacall),
//  method_offset/method_relative (slot metodu), signal_index...
//  Boylece "bu butonun clicked() olayina bagli kod VAR MI?" sorusu
//  harici bellek okumasiyla tam yanitlanir. (XPRO event tespitinin Qt bedeni)
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "qt_layouts.h"
#include "qt_metaobject.h"
#include "qt_scan.h"

namespace umvpqt {

class ConnectionWalker {
public:
    ConnectionWalker(IProcessReader& proc, const QtLayouts& L, ClassRegistry& reg)
        : proc_(proc), L_(L), reg_(reg) {}

    // Bir QObject'in tum (giden) sinyal baglantilarini toplar
    // objAddr: QObject adresi
    std::vector<ConnectionInfo> outgoing(Addr objAddr, int signalCountHint = -1);

    // Tum taranan nesneler icin baglantilari toplar (tek kisaltma listesi)
    std::vector<ConnectionInfo> collect(const std::vector<Addr>& objects,
                                        const std::map<Addr, MetaClassInfo>& classOf);

private:
    // Connection'dan okunabilir isim/imza uret
    void describe(ConnectionInfo& ci);
    IProcessReader& proc_;
    const QtLayouts& L_;
    ClassRegistry& reg_;
};

} // namespace umvpqt
