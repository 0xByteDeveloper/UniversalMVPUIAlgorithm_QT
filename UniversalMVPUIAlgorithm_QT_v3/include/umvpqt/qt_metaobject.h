// UMVPQT GOD STATE — QMetaObject Parser (Qt4/Qt5/Qt6 eralari)
// ============================================================================
//  QMetaObject bellek yapisini (PDB'siz, harici okuma ile) cozer:
//    Qt6: d = [superdata][stringdata(uint*)][data(uint*)][static_metacall]...
//         stringdata[i] = {offset(uint), length(uint)} ciftleri
//         data   : 14-int header + methodlar (6 int) + property'ler (5 int)...
//    Qt5: d = [superdata][stringdata(QByteArrayData*)][data][static_metacall]...
//         stringdata: QByteArrayData[24B] baslik tablosu + char blob
//         data   : 14-int header + methodlar (5 int) + property (3 int) + notify
//  Tum metod isimleri/imzalari/flag'leri ve sinif hiyerarsisi cikarilir.
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "qt_layouts.h"
#include "qt_strings.h"
#include "module.h"

namespace umvpqt {

class MetaObjectParser {
public:
    MetaObjectParser(IProcessReader& proc, const QtLayouts& lay, const ModuleTable& mt)
        : proc_(proc), L(lay), mt_(mt) {}

    // QMetaObject adresini parse et (guvenlik kontrolu ile)
    bool parse(Addr moAddr, MetaClassInfo& out);

    // Su kontrolu: adres gercekten QMetaObject mi? (data revision + stringdata okunabilirlik)
    bool looksLikeMetaObject(Addr moAddr, int* revisionOut = nullptr);

    // Sinif zinciri (QObject'a kadar) — superdata takibi
    static bool classChain(IProcessReader& proc, const QtLayouts& L, Addr moAddr,
                           std::vector<Addr>& chainOut);

    // Mo erasina gore string coz
    std::string readMetaString(Addr stringdataAddr, uint32_t index, QtEra era, int revision);

    // Metot index'i (tum zincirdeki global index) coz:
    //   methodOffset hesabi: superdata zincirindeki methodCount toplami
    int absoluteMethodIndex(Addr moAddr, int relativeIndex);

private:
    IProcessReader& proc_;
    const QtLayouts& L;
    const ModuleTable& mt_;
};

// ---- QMetaObject::d alanlari (layout'tan) ----
struct MoView {
    Addr superdata = 0, stringdata = 0, data = 0, static_metacall = 0,
         relatedMetaObjects = 0, metaTypes = 0, extradata = 0;
};

inline MoView moView(IProcessReader& proc, const QtLayouts& L, Addr mo) {
    MoView v;
    v.superdata   = proc.readAddr(mo + L.mo_superdata);
    v.stringdata  = proc.readAddr(mo + L.mo_stringdata);
    v.data         = proc.readAddr(mo + L.mo_data);
    v.static_metacall = proc.readAddr(mo + L.mo_static_metacall);
    v.relatedMetaObjects = proc.readAddr(mo + L.mo_relatedMetaObjects);
    if (L.mo_metaTypes != 0xFFFFFFFFu) v.metaTypes = proc.readAddr(mo + L.mo_metaTypes);
    return v;
}

} // namespace umvpqt
