// UMVPQT GOD STATE — Qt Layout Runtime
// ============================================================================
//  Layout cozumleme katmani:
//    1) Gomulu DB'ler: Qt 5.15.15 + Qt 6.8.2 (tools/gen_layout offsetof probu)
//    2) 32-bit hedefler: genislik-imzali (P/I/S) rescaler — 64-bit tablodan turetir
//    3) Bilinmeyen surumler: runtime kalibrasyon (q_ptr geri-bag + agac invariantlari)
//  Butun alanlar tek QtLayouts yapisinda toplanir.
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "module.h"
#include <string>

namespace umvpqt {

struct QtLayouts {
    // ---------- QObjectData ----------
    unsigned q_ptr = 8, parent = 16, children = 24;       // QList/QObjectList
    unsigned flags_bits = 48;                              // bitfield blogu
    unsigned isWidget_bit = 0, wasDeleted_bit = 2, isWindow_bit = 6;
    unsigned postedEvents = 52, metaObject_ptr = 56;
    unsigned sz_QObjectData = 72;

    // ---------- QObjectPrivate ----------
    unsigned extraData = 72, threadData = 80, connections = 88, currentChild = 88, sharedRefcount = 104;
    unsigned sz_QObjectPrivate = 112;

    // ---------- ExtraData ----------
    unsigned ed_propertyNames = 0, ed_propertyValues = 24, ed_runningTimers = 48,
             ed_eventFilters = 72, ed_objectName = 96;      // qt5'te gecerli; qt6 compat-prop
    bool     hasPlainObjectName = false;                    // Qt5

    // ---------- QMetaObject ----------
    unsigned mo_superdata = 0, mo_stringdata = 8, mo_data = 16, mo_static_metacall = 24,
             mo_relatedMetaObjects = 32, mo_metaTypes = 40, mo_extradata = 48;
    unsigned sz_QMetaObject = 56;
    bool     qt6Layout = true;                              // metaTypes alanli mi

    // ---------- Connection ----------
    unsigned cn_prev = 8, cn_nextConnectionList = 16, cn_prevConnectionList = 24,
             cn_sender = 32, cn_receiver = 40, cn_receiverThreadData = 48,
             cn_callFunction = 56, cn_argumentTypes = 64, cn_ref = 72, cn_id = 76,
             cn_method_offset = 80, cn_method_relative = 82, cn_bits = 84;
    unsigned sz_Connection = 88;
    unsigned connType_3bit = false;                         // Qt5: 3 bit

    // ---------- ConnectionData / SignalVector ----------
    unsigned cd_signalVector = 8, cd_senders = 16;
    unsigned sv_allocated = 8, sv_lists = 16;
    unsigned sz_ConnectionList = 16;

    // ---------- QString / QList (Qt6: [d][ptr][size]) ----------
    unsigned qs_d = 0, qs_ptr = 8, qs_size = 16, sz_QString = 24;
    unsigned ql_d = 0, ql_ptr = 8, ql_size = 16, sz_QList = 24;
    bool     listUsesHeader = false;                         // Qt5: veri d+QArrayData+offset

    // ---------- QArrayData ----------
    unsigned ad_ref = 0, ad_size = 4, ad_alloc = 8, ad_offset = 16, sz_QArrayData = 24;

    // ---------- QWidgetData ----------
    unsigned wd_winid = 0, wd_widget_attributes = 8, wd_window_flags = 12,
             wd_crect = 24, wd_pal = 40, wd_fnt = 48, wd_wrect = 56;
    unsigned sz_QWidgetData = 72;

    // ---------- QWidgetPrivate ----------
    unsigned wp_extra = 112, wp_data = 0, wp_toolTip = 0, wp_layout = 0,
             wp_focus_next = 0, wp_hd = 0;
    unsigned sz_QWidgetPrivate = 0;

    // ---------- QWExtra / QTLWExtra ----------
    unsigned qwe_topextra = 0;
    unsigned tle_caption = 40;   // windowTitle
    unsigned tle_icon = 0, tle_window = 32, tle_backingStore = 16;

    // ---------- QAbstractButtonPrivate ----------
    unsigned ab_text = 0;

    // ---------- QLabelPrivate ----------
    unsigned lb_text = 0;

    // ---------- QComboBoxPrivate ----------
    unsigned cb_model = 0, cb_lineEdit = 0, cb_container = 0, cb_currentIndex = 0,
             cb_root = 0, cb_currentText = 0, cb_placeholderText = 0, cb_maxVisibleItems = 0;
    unsigned cb_modelConnections = 0;
    bool     cb_hasCurrentText = false;

    // ---------- QLineEdit ----------
    unsigned le_control = 0;
    unsigned wlc_m_text = 0;

    // ---------- QStandardItem ----------
    unsigned si_values = 0, si_children = 0, si_model = 0, si_parent = 0,
             si_rows = 0, si_columns = 0, si_q_ptr = 0;
    unsigned sid_role = 0, sid_value = 8;
    unsigned sim_root = 0;   // QStandardItemModelPrivate::root (QScopedPointer -> P)

    // ---------- QModelIndex ----------
    unsigned mi_r = 0, mi_c = 4, mi_i = 8, mi_m = 16, sz_QModelIndex = 24;
    unsigned pmi_d = 0;

    // ---------- QVariant ----------
    unsigned qv_d = 0, sz_QVariant = 32;

    // ---------- MetaObject data ----------  // QMetaMethod::Data { name argc parameters tag flags metaTypeOffset }
    unsigned mo_IntsPerMethod = 6, mo_IntsPerProperty = 3, mo_IntsPerEnum = 8, mo_HeaderInts = 14;

    // ---------- Attribute bitleri ----------  // QMetaMethod::Data { name argc parameters tag flags metaTypeOffset }
    unsigned WA_Visible = 10, WA_Mapped = 12;

    // ---- cozumleme ----
    bool resolve(const QtInfo& info, IProcessReader& proc);   // DB/secim/kalibrasyon

    // 32-bit rescale: verilen imza dizisiyle 64-bit tablosundan 32-bit tablosu uret
    // imza: her alan icin genislik sinifi ('P' ptr, 'I' int, 'S' short, 'B' byte, 'Q' int64)
    struct FieldSig { const char* name; char cls; };
    static unsigned rescaleField(const std::vector<unsigned>& offs64, const std::vector<char>& cls,
                                  size_t idx, int ptrW);
};

// Kalibrasyon: bilinmeyen Qt surumlerinde anaklar (anchor) uzerinden
// QObjectData::children / QWidgetPrivate::data offsetlerini tespit eder.
struct LayoutCalibrator {
    IProcessReader* proc = nullptr;
    // d-ptr bloğunda cocuk listesi (d, ptr, size) oruntusunu ara:
    // ptr[i]'ler gecerli QObject (q_ptr geri-bag) olmali.
    static bool findChildrenField(IProcessReader& proc, Addr d, Addr self,
                                  unsigned searchLo, unsigned searchHi,
                                  unsigned& outChildrenOff, unsigned& outParentOff);
};

} // namespace umvpqt
