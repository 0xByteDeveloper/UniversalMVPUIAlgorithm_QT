// UMVPQT GOD STATE — Qt Layout Runtime implementation
// ============================================================================
//  Gomulu DB'ler (namespace icinde) + secim + 32-bit rescale + kalibrasyon.
// ============================================================================
#include "umvpqt/qt_layouts.h"
#include <vector>
#include <cstring>
#include <algorithm>

namespace umvpqt {

// gomulu DB'ler (namespace icinde) + secim + 32-bit rescale + kalibrasyon.
// DB'ler bu tipi tanimlamaz (uretimde strip edilir) — biz tanimlariz:
struct UmvpQtLayoutEntry { const char* name; unsigned off; };

namespace qt6db {
#include "generated/qt_layout_db_qt6.h"
}
namespace qt5db {
#include "generated/qt_layout_db_qt5.h"
}

static unsigned dbFind(const UmvpQtLayoutEntry* arr, size_t n, const char* name) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0) return arr[i].off;
    return 0xFFFFFFFFu;
}
#define DBF(db, arr, field) dbFind(db::arr, sizeof(db::arr) / sizeof(db::arr[0]), field)

// ------------------------------------------------ rescale yardimci -------
unsigned QtLayouts::rescaleField(const std::vector<unsigned>& offs64, const std::vector<char>& cls,
                                 size_t idx, int ptrW) {
    // offs64: 64-bit offsetleri (sirali alanlar); cls: genislik sinifi
    // 32-bitte P alanlar 4 bayt olur, Q(8) ve I(4)/S(2) degismez; hizalama yeniden hesaplanir.
    if (idx >= offs64.size()) return 0;
    unsigned off = 0;
    for (size_t i = 0; i <= idx; i++) {
        unsigned width = cls[i] == 'P' ? (unsigned)ptrW
                       : cls[i] == 'Q' ? 8
                       : cls[i] == 'I' ? 4
                       : cls[i] == 'S' ? 2
                       : 1;
        unsigned align = (width >= 8 && cls[i] == 'Q') ? 8
                        : (width == 4 || cls[i] == 'P') ? 4 : width;
        if (ptrW == 4 && cls[i] == 'Q') align = 4;
        off = (off + align - 1) & ~(align - 1);
        if (i == idx) return off;
        off += width;
    }
    return off;
}

// ------------------------------------------------ cozumleme -------------
bool QtLayouts::resolve(const QtInfo& info, IProcessReader& proc) {
    int ptrW = proc.ptrSize();
    bool qt6 = info.era != QtEra::Qt5 && info.era != QtEra::Qt4;

    if (qt6) {
        // ---------------- Qt 6.8 DB (6.0-6.7 icin kalibrasyonla duzeltilir) ----
        q_ptr             = DBF(qt6db, L_QObjectData, "q_ptr");
        parent            = DBF(qt6db, L_QObjectData, "parent");
        children          = DBF(qt6db, L_QObjectData, "children");
        postedEvents      = DBF(qt6db, L_QObjectData, "postedEvents");
        metaObject_ptr    = DBF(qt6db, L_QObjectData, "metaObject");
        flags_bits        = qt6db::O_QObjectData_flags_bitfield;
        sz_QObjectData    = qt6db::SZ_QObjectData;

        extraData         = DBF(qt6db, L_QObjectPrivate, "extraData");
        threadData        = DBF(qt6db, L_QObjectPrivate, "threadData");
        connections       = DBF(qt6db, L_QObjectPrivate, "connections");
        currentChild      = qt6db::O_QObjectPrivate_currentChild;
        sz_QObjectPrivate = qt6db::SZ_QObjectPrivate;

        ed_propertyNames  = DBF(qt6db, L_QObjectExtraData, "propertyNames");
        ed_propertyValues = DBF(qt6db, L_QObjectExtraData, "propertyValues");
        ed_runningTimers  = DBF(qt6db, L_QObjectExtraData, "runningTimers");
        ed_eventFilters   = DBF(qt6db, L_QObjectExtraData, "eventFilters");
        hasPlainObjectName = false;   // Qt6: compat property — runtime sm probing

        mo_superdata      = DBF(qt6db, L_QMetaObject, "d.superdata");
        mo_stringdata     = DBF(qt6db, L_QMetaObject, "d.stringdata");
        mo_data           = DBF(qt6db, L_QMetaObject, "d.data");
        mo_static_metacall= DBF(qt6db, L_QMetaObject, "d.static_metacall");
        mo_relatedMetaObjects = DBF(qt6db, L_QMetaObject, "d.relatedMetaObjects");
        mo_metaTypes      = DBF(qt6db, L_QMetaObject, "d.metaTypes");
        mo_extradata      = DBF(qt6db, L_QMetaObject, "d.extradata");
        sz_QMetaObject    = qt6db::SZ_QMetaObject;
        qt6Layout         = true;

        cn_prev            = DBF(qt6db, L_Connection, "prev");
        cn_nextConnectionList = DBF(qt6db, L_Connection, "nextConnectionList");
        cn_prevConnectionList = DBF(qt6db, L_Connection, "prevConnectionList");
        cn_sender          = DBF(qt6db, L_Connection, "sender");
        cn_receiver        = DBF(qt6db, L_Connection, "receiver");
        cn_receiverThreadData = DBF(qt6db, L_Connection, "receiverThreadData");
        cn_callFunction    = DBF(qt6db, L_Connection, "callFunction");
        cn_argumentTypes   = DBF(qt6db, L_Connection, "argumentTypes");
        cn_ref             = DBF(qt6db, L_Connection, "ref_");
        cn_id              = DBF(qt6db, L_Connection, "id");
        cn_method_offset   = DBF(qt6db, L_Connection, "method_offset");
        cn_method_relative = DBF(qt6db, L_Connection, "method_relative");
        sz_Connection      = qt6db::SZ_Connection;
        connType_3bit      = false;

        cd_signalVector    = DBF(qt6db, L_ConnectionData, "signalVector");
        cd_senders         = DBF(qt6db, L_ConnectionData, "senders");
        sv_allocated       = DBF(qt6db, L_SignalVector, "allocated");
        sv_lists           = qt6db::O_SignalVector_lists;
        sz_ConnectionList  = qt6db::SZ_ConnectionList;

        qs_d      = qt6db::O_QString_d;
        qs_ptr    = qt6db::O_QString_ptr;
        qs_size   = qt6db::O_QString_size;
        sz_QString= qt6db::SZ_QString;
        ql_d      = qt6db::O_QList_d;
        ql_ptr    = qt6db::O_QList_ptr;
        ql_size   = qt6db::O_QList_size;
        sz_QList  = qt6db::SZ_QList;
        listUsesHeader = false;

        ad_ref = 0; ad_size = 0xFFFFFFFFu; ad_alloc = 8; ad_offset = 0xFFFFFFFFu; sz_QArrayData = 16;
        // Qt6 QArrayData { ref(4) flags(4) alloc(8) } — veri ptr'den onceki header

        wd_winid           = DBF(qt6db, L_QWidgetData, "winid");
        wd_widget_attributes= DBF(qt6db, L_QWidgetData, "widget_attributes");
        wd_window_flags    = DBF(qt6db, L_QWidgetData, "window_flags");
        wd_crect           = DBF(qt6db, L_QWidgetData, "crect");
        wd_pal             = DBF(qt6db, L_QWidgetData, "pal");
        wd_fnt             = DBF(qt6db, L_QWidgetData, "fnt");
        wd_wrect           = DBF(qt6db, L_QWidgetData, "wrect");
        sz_QWidgetData     = qt6db::SZ_QWidgetData;

        wp_extra   = DBF(qt6db, L_QWidgetPrivate, "extra");
        wp_data    = DBF(qt6db, L_QWidgetPrivate, "data");
        wp_toolTip = DBF(qt6db, L_QWidgetPrivate, "toolTip");
        wp_layout  = DBF(qt6db, L_QWidgetPrivate, "layout");
        wp_focus_next = DBF(qt6db, L_QWidgetPrivate, "focus_next");
        wp_hd      = DBF(qt6db, L_QWidgetPrivate, "hd");
        sz_QWidgetPrivate = qt6db::SZ_QWidgetPrivate;

        qwe_topextra = DBF(qt6db, L_QWExtra, "topextra");
        tle_caption  = DBF(qt6db, L_QTLWExtra, "caption");
        tle_window   = DBF(qt6db, L_QTLWExtra, "window");
        tle_backingStore = DBF(qt6db, L_QTLWExtra, "backingStore");

        ab_text = DBF(qt6db, L_QAbstractButtonPrivate, "text");
        lb_text = DBF(qt6db, L_QLabelPrivate, "text");

        cb_model           = DBF(qt6db, L_QComboBoxPrivate, "model");
        cb_lineEdit        = DBF(qt6db, L_QComboBoxPrivate, "lineEdit");
        cb_container       = DBF(qt6db, L_QComboBoxPrivate, "container");
        cb_currentIndex     = DBF(qt6db, L_QComboBoxPrivate, "currentIndex");
        cb_root            = DBF(qt6db, L_QComboBoxPrivate, "root");
        cb_currentText     = DBF(qt6db, L_QComboBoxPrivate, "currentText");
        cb_placeholderText = DBF(qt6db, L_QComboBoxPrivate, "placeholderText");
        cb_maxVisibleItems = DBF(qt6db, L_QComboBoxPrivate, "maxVisibleItems");
        cb_modelConnections= DBF(qt6db, L_QComboBoxPrivate, "modelConnections");
        cb_hasCurrentText  = true;

        le_control   = DBF(qt6db, L_QLineEditPrivate, "control");
        wlc_m_text   = DBF(qt6db, L_QWidgetLineControl, "m_text");

        si_values   = DBF(qt6db, L_QStandardItemPrivate, "values");
        si_children = DBF(qt6db, L_QStandardItemPrivate, "children");
        si_model    = DBF(qt6db, L_QStandardItemPrivate, "model");
        si_parent   = DBF(qt6db, L_QStandardItemPrivate, "parent");
        si_rows     = DBF(qt6db, L_QStandardItemPrivate, "rows");
        si_columns  = DBF(qt6db, L_QStandardItemPrivate, "columns");
        sid_role    = DBF(qt6db, L_QStandardItemData, "role");
        sid_value   = DBF(qt6db, L_QStandardItemData, "value");
        sim_root    = DBF(qt6db, L_QStandardItemModelPrivate, "root");

        mi_r = DBF(qt6db, L_QModelIndex, "r");
        mi_c = DBF(qt6db, L_QModelIndex, "c");
        mi_i = DBF(qt6db, L_QModelIndex, "i");
        mi_m = DBF(qt6db, L_QModelIndex, "m");
        sz_QModelIndex = qt6db::SZ_QModelIndex;
        pmi_d = DBF(qt6db, L_QPersistentModelIndex, "d");

        qv_d    = qt6db::O_QVariant_d;
        sz_QVariant = qt6db::SZ_QVariant;

        mo_IntsPerMethod    = qt6db::QMO_IntsPerMethod;
        mo_IntsPerProperty  = qt6db::QMO_IntsPerProperty;
        mo_IntsPerEnum      = qt6db::QMO_IntsPerEnum;
        mo_HeaderInts       = qt6db::QMO_HeaderInts;

        WA_Visible = qt6db::WA_WState_Visible;
        WA_Mapped  = qt6db::WA_Mapped;
    } else {
        // ---------------- Qt 5.15 DB --------------------------------------
        q_ptr             = DBF(qt5db, L_QObjectData, "q_ptr");
        parent            = DBF(qt5db, L_QObjectData, "parent");
        children          = DBF(qt5db, L_QObjectData, "children");
        postedEvents      = DBF(qt5db, L_QObjectData, "postedEvents");
        metaObject_ptr    = DBF(qt5db, L_QObjectData, "metaObject");
        flags_bits        = qt5db::O_QObjectData_flags_bitfield;
        sz_QObjectData    = qt5db::SZ_QObjectData;

        extraData         = DBF(qt5db, L_QObjectPrivate, "extraData");
        threadData        = DBF(qt5db, L_QObjectPrivate, "threadData");
        connections       = DBF(qt5db, L_QObjectPrivate, "connections");
        currentChild      = qt5db::O_QObjectPrivate_currentChild;
        sz_QObjectPrivate = qt5db::SZ_QObjectPrivate;

        ed_propertyNames  = DBF(qt5db, L_QObjectExtraData, "propertyNames");
        ed_propertyValues = DBF(qt5db, L_QObjectExtraData, "propertyValues");
        ed_runningTimers  = DBF(qt5db, L_QObjectExtraData, "runningTimers");
        ed_eventFilters   = DBF(qt5db, L_QObjectExtraData, "eventFilters");
        ed_objectName     = DBF(qt5db, L_QObjectExtraData, "objectName");
        hasPlainObjectName = true;

        mo_superdata      = DBF(qt5db, L_QMetaObject, "d.superdata");
        mo_stringdata     = DBF(qt5db, L_QMetaObject, "d.stringdata");
        mo_data           = DBF(qt5db, L_QMetaObject, "d.data");
        mo_static_metacall= DBF(qt5db, L_QMetaObject, "d.static_metacall");
        mo_relatedMetaObjects = DBF(qt5db, L_QMetaObject, "d.relatedMetaObjects");
        mo_metaTypes      = 0xFFFFFFFFu;
        mo_extradata      = DBF(qt5db, L_QMetaObject, "d.extradata");
        sz_QMetaObject    = qt5db::SZ_QMetaObject;
        qt6Layout         = false;

        cn_prev            = DBF(qt5db, L_Connection, "prev");
        cn_nextConnectionList = DBF(qt5db, L_Connection, "nextConnectionList");
        cn_prevConnectionList = DBF(qt5db, L_Connection, "prevConnectionList");
        cn_sender          = DBF(qt5db, L_Connection, "sender");
        cn_receiver        = DBF(qt5db, L_Connection, "receiver");
        cn_receiverThreadData = DBF(qt5db, L_Connection, "receiverThreadData");
        cn_callFunction    = DBF(qt5db, L_Connection, "callFunction");
        cn_argumentTypes   = DBF(qt5db, L_Connection, "argumentTypes");
        cn_ref             = DBF(qt5db, L_Connection, "ref_");
        cn_id              = DBF(qt5db, L_Connection, "id");
        cn_method_offset   = DBF(qt5db, L_Connection, "method_offset");
        cn_method_relative = DBF(qt5db, L_Connection, "method_relative");
        sz_Connection      = qt5db::SZ_Connection;
        connType_3bit      = true;

        cd_signalVector    = DBF(qt5db, L_ConnectionData, "signalVector");
        cd_senders         = DBF(qt5db, L_ConnectionData, "senders");
        sv_allocated       = DBF(qt5db, L_SignalVector, "allocated");
        sv_lists           = qt5db::O_SignalVector_lists;
        sz_ConnectionList  = qt5db::SZ_ConnectionList;

        // Qt5: QString = { QStringData *d } — veri: d + QArrayData.offset
        qs_d = 0; qs_ptr = 0xFFFFFFFFu; qs_size = 0xFFFFFFFFu;
        sz_QString = qt5db::SZ_QString;
        ql_d      = qt5db::O_QList_d;
        ql_ptr    = 0xFFFFFFFFu;
        ql_size   = 0xFFFFFFFFu;
        sz_QList  = qt5db::SZ_QList;
        listUsesHeader = true;

        ad_ref = 0; ad_size = 4; ad_alloc = 8; ad_offset = 16; sz_QArrayData = 24;

        wd_winid           = DBF(qt5db, L_QWidgetData, "winid");
        wd_widget_attributes= DBF(qt5db, L_QWidgetData, "widget_attributes");
        wd_window_flags    = DBF(qt5db, L_QWidgetData, "window_flags");
        wd_crect           = DBF(qt5db, L_QWidgetData, "crect");
        wd_pal             = DBF(qt5db, L_QWidgetData, "pal");
        wd_fnt             = DBF(qt5db, L_QWidgetData, "fnt");
        wd_wrect           = DBF(qt5db, L_QWidgetData, "wrect");
        sz_QWidgetData     = qt5db::SZ_QWidgetData;

        wp_extra   = DBF(qt5db, L_QWidgetPrivate, "extra");
        wp_data    = DBF(qt5db, L_QWidgetPrivate, "data");
        wp_toolTip = DBF(qt5db, L_QWidgetPrivate, "toolTip");
        wp_layout  = DBF(qt5db, L_QWidgetPrivate, "layout");
        wp_focus_next = DBF(qt5db, L_QWidgetPrivate, "focus_next");
        wp_hd      = DBF(qt5db, L_QWidgetPrivate, "hd");
        sz_QWidgetPrivate = qt5db::SZ_QWidgetPrivate;

        qwe_topextra = DBF(qt5db, L_QWExtra, "topextra");
        tle_caption  = DBF(qt5db, L_QTLWExtra, "caption");
        tle_window   = DBF(qt5db, L_QTLWExtra, "window");
        tle_backingStore = DBF(qt5db, L_QTLWExtra, "backingStore");

        ab_text = DBF(qt5db, L_QAbstractButtonPrivate, "text");
        lb_text = DBF(qt5db, L_QLabelPrivate, "text");

        cb_model           = DBF(qt5db, L_QComboBoxPrivate, "model");
        cb_lineEdit        = DBF(qt5db, L_QComboBoxPrivate, "lineEdit");
        cb_container       = DBF(qt5db, L_QComboBoxPrivate, "container");
        cb_currentIndex     = DBF(qt5db, L_QComboBoxPrivate, "currentIndex");
        cb_root            = DBF(qt5db, L_QComboBoxPrivate, "root");
        cb_currentText     = 0xFFFFFFFFu;
        cb_placeholderText = DBF(qt5db, L_QComboBoxPrivate, "placeholderText");
        cb_maxVisibleItems = DBF(qt5db, L_QComboBoxPrivate, "maxVisibleItems");
        cb_modelConnections= 0xFFFFFFFFu;
        cb_hasCurrentText  = false;

        le_control   = DBF(qt5db, L_QLineEditPrivate, "control");
        wlc_m_text   = DBF(qt5db, L_QWidgetLineControl, "m_text");

        si_values   = DBF(qt5db, L_QStandardItemPrivate, "values");
        si_children = DBF(qt5db, L_QStandardItemPrivate, "children");
        si_model    = DBF(qt5db, L_QStandardItemPrivate, "model");
        si_parent   = DBF(qt5db, L_QStandardItemPrivate, "parent");
        si_rows     = DBF(qt5db, L_QStandardItemPrivate, "rows");
        si_columns  = DBF(qt5db, L_QStandardItemPrivate, "columns");
        sid_role    = DBF(qt5db, L_QStandardItemData, "role");
        sid_value   = DBF(qt5db, L_QStandardItemData, "value");
        sim_root    = DBF(qt5db, L_QStandardItemModelPrivate, "root");

        mi_r = DBF(qt5db, L_QModelIndex, "r");
        mi_c = DBF(qt5db, L_QModelIndex, "c");
        mi_i = DBF(qt5db, L_QModelIndex, "i");
        mi_m = DBF(qt5db, L_QModelIndex, "m");
        sz_QModelIndex = qt5db::SZ_QModelIndex;
        pmi_d = DBF(qt5db, L_QPersistentModelIndex, "d");

        qv_d    = qt5db::O_QVariant_d;
        sz_QVariant = qt5db::SZ_QVariant;

        mo_IntsPerMethod    = qt5db::QMO_IntsPerMethod;
        mo_IntsPerProperty  = qt5db::QMO_IntsPerProperty;
        mo_IntsPerEnum      = qt5db::QMO_IntsPerEnum;
        mo_HeaderInts       = qt5db::QMO_HeaderInts;

        WA_Visible = qt5db::WA_WState_Visible;
        WA_Mapped  = qt5db::WA_Mapped;
    }

    // --------------------------------------------- 32-bit rescale --------
    if (ptrW == 4) {
        // QObjectData: [vptr P][q_ptr P][parent P][children {P P P}][flags I][posted I][metaObj P][binding P]
        {
            const std::vector<unsigned> o{ 0, 8, 16, 24 };
            const std::vector<char> c{ 'P','P','P','P' };
            q_ptr   = rescaleField(o, c, 1, 4);
            parent  = rescaleField(o, c, 2, 4);
            children= rescaleField(o, c, 3, 4);
            // cocuk listesi 3 * 4 = 12 bayt; flags: 12+12=24? hizalama int
            flags_bits = children + 12;          // int hizali
            postedEvents = flags_bits + 4;
            metaObject_ptr = postedEvents + 4;
            sz_QObjectData = metaObject_ptr + 4;
            // bindingStorage (Qt6) + QObjectPrivate ekleyecegiz:
            // QObjectPrivate: extraData P, (Qt6.0-6.7: parent P + children 12 byte yok! sadece 6.8'de QObjectData'da)
            // Not: 32-bit Qt6'da bindingStorage 4 byte; extraData 4...
            extraData = sz_QObjectData;      // 6.8 duzeni (kalibrasyonla duzelir)
            threadData = extraData + 4;
            connections = threadData + 4;
            currentChild = connections + 4;
            sharedRefcount = currentChild + 4;
            sz_QObjectPrivate = sharedRefcount + 4;
        }
        // QMetaObject: 6-7 * P
        {
            mo_superdata = 0; mo_stringdata = 4; mo_data = 8; mo_static_metacall = 12;
            mo_relatedMetaObjects = 16;
            if (qt6Layout) { mo_metaTypes = 20; mo_extradata = 24; sz_QMetaObject = 28; }
            else { mo_metaTypes = 0xFFFFFFFFu; mo_extradata = 20; sz_QMetaObject = 24; }
        }
        // Connection: [P][P][P][P][P][P][P][P][P][I][I][S][S][bits]
        {
            cn_prev = 4; cn_nextConnectionList = 8; cn_prevConnectionList = 12;
            cn_sender = 16; cn_receiver = 20; cn_receiverThreadData = 24;
            cn_callFunction = 28; cn_argumentTypes = 32;
            cn_ref = 36; cn_id = 40; cn_method_offset = 44; cn_method_relative = 46; cn_bits = 48;
            sz_Connection = 52;
        }
        // ConnectionData: [I][I][P][P][P][P]
        { cd_signalVector = 8; cd_senders = 12; sv_allocated = 4; sv_lists = 8; sz_ConnectionList = 8; }
        // QString: Qt6 [P][P][I]; Qt5 [P]
        if (qt6Layout) { qs_d = 0; qs_ptr = 4; qs_size = 8; sz_QString = 12; }
        else { qs_d = 0; sz_QString = 4; }
        // QList: Qt6 [P][P][I]; Qt5 [P]
        if (qt6Layout) { ql_d = 0; ql_ptr = 4; ql_size = 8; sz_QList = 12; }
        else { ql_d = 0; sz_QList = 4; }
        // QArrayData: Qt5 { I I I pad Q(offset) } = 16; Qt6 { I I Q } = 16
        if (!qt6Layout) { ad_offset = 12; sz_QArrayData = 16; }
        else { ad_alloc = 8; sz_QArrayData = 16; }
        // QWidgetData: [P winid][I attrs][I flags][I bits][pad][crect 4*I][pal P][fnt P][wrect 4*I]
        {
            wd_winid = 0; wd_widget_attributes = 4; wd_window_flags = 8;
            // bitfield uint 4 + pad 4
            wd_crect = 20; wd_pal = 36; wd_fnt = 40; wd_wrect = 44; sz_QWidgetData = 60;
        }
        // QTLWExtra: [icon P][repMgr P][backStore P][sharedP P][window P][caption QS][iconText QS]...
        {
            unsigned qs = qt6Layout ? 12 : 4;
            tle_backingStore = 8; tle_window = 16;
            tle_caption = 20 + qs;   // 5 isaretci + QString
            qwe_topextra = 0;        // QWExtra basi (glContext P + topextra P)
            // QWExtra: glContext P, topextra P, [proxy P], [curs P], style P, focus P, ... minw...
        }
        // QAbstractButtonPrivate::text — QWidgetPrivate sonrasi ilk QString
        {
            // kabaca: 32-bitte de "text" QWidgetPrivate boyutunun hemen ardinda; kalibrasyon devreye girer
            ab_text = 0; lb_text = 0; le_control = 0; wlc_m_text = 0;
        }
        // QModelIndex: [I r][I c][P i(=quintptr 4?)][P m]
        { mi_r = 0; mi_c = 4; mi_i = 8; mi_m = 12; sz_QModelIndex = 16; pmi_d = 0; }
        // QVariant: Qt6 { data 3*P=12 + bits P=4 } = 16; Qt5 { I + P + P } = 12
        if (qt6Layout) { qv_d = 0; sz_QVariant = 16; }
        else { qv_d = 0; sz_QVariant = 12; }
    }

    return true;
}

// ------------------------------------------------ kalibrasyon ----------
bool LayoutCalibrator::findChildrenField(IProcessReader& proc, Addr d, Addr self,
                                          unsigned searchLo, unsigned searchHi,
                                          unsigned& outChildrenOff, unsigned& outParentOff) {
    // d noktasinda searchLo..searchHi arasinda (listD, ptr, size) oruntusu ara;
    // ptr[i] gecerli QObject olmali (q_ptr geri-bag) ve listede self olmali.
    for (unsigned off = searchLo; off + 24 <= searchHi; off += 8) {
        Addr dPtr = proc.readAddr(d + off);
        Addr ptr  = proc.readAddr(d + off + 8);
        uint64_t size = proc.readAddr(d + off + 16);   // qsizetype
        if (size == 0 || size > 2000) continue;
        if (!ptr || ptr == dPtr) continue;
        if (size > 64) continue;
        // orneklem: ilk 4 cocuk
        int hits = 0, checks = 0;
        for (uint64_t i = 0; i < size && i < 4; i++) {
            Addr c = proc.readAddr(ptr + i * proc.ptrSize());
            checks++;
            if (!c) continue;
            Addr cd = proc.readAddr(c + proc.ptrSize());
            if (!cd) continue;
            if (proc.readAddr(cd + 8) == c) hits++;
        }
        if (checks >= 2 && hits >= checks - 1) {
            outChildrenOff = off;
            // parent: listede self'i iceren listeden onceki pointer alani — simdilik
            // parent = cocuklarin ortak parent'i: (d + off - 8) heuristigi kalibrasyon katmaninda
            outParentOff = off - 8;
            return true;
        }
    }
    return false;
}

} // namespace umvpqt
