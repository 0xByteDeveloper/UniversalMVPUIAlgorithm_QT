// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT
// Qt 5.15 ABI REPLICA (x64) — field order copied 1:1 from qtbase/5.15 sources:
//   src/corelib/kernel/qobject.h         (QObjectData)
//   src/corelib/kernel/qobject_p.h        (QObjectPrivate, Connection, ...)
//   src/corelib/kernel/qobjectdefs.h      (QMetaObject)
//   src/corelib/kernel/qmetaobject_p.h    (QMetaObjectPrivate)
//   src/corelib/tools/qarraydata.h        (QArrayData)
//   src/corelib/tools/qlist.h             (QListData)
//   src/corelib/text/qstring.h            (QString)
//   src/widgets/kernel/qwidget.h          (QWidgetData, QWidget)
// The structs are plain (no Qt macros); offsetof() on these == real Qt x64
// layout because field order, types and sizes match. Verified against
// qtbase ref "5.15" (fetched Nov 2026).
// =============================================================================
#pragma once
#include <cstdint>

namespace umvpqt_replica_qt5 {

using i8  = int8_t;  using u8  = uint8_t;
using i16 = int16_t; using u16 = uint16_t;
using i32 = int32_t; using u32 = uint32_t;
using i64 = int64_t; using u64 = uint64_t;

// --- atomics (same size as Qt's QBasicAtomicInt) ----------------------------
struct QAtomicInt { volatile i32 v; };      // sizeof 4
struct RefCounted   { QAtomicInt a; };      // QtPrivate::RefCountedData

// --- QArrayData (Qt 5.15, x64: 4+4+4+pad4+8 = 24) ---------------------------
struct QArrayData {
    RefCounted ref;        // 0
    i32 size;              // 4
    u32 alloc : 31;        // 8
    u32 capacityReserved : 1;
    i64 offset;            // 16 (qptrdiff, 8-aligned)
};
struct QStringDataRep : QArrayData {
    const char16_t* chars() const {
        return reinterpret_cast<const char16_t*>(
            reinterpret_cast<const char*>(this) + offset);
    }
};

// --- QString (Qt5: single d pointer, sizeof 8) -------------------------------
struct QString5 {
    QStringDataRep* d;     // 0
};

// --- QListData (Qt 5.15, qlist.h) ---------------------------------------------
struct QListData {
    struct Data {
        RefCounted ref;    // 0
        i32 alloc;         // 4
        i32 begin;         // 8
        i32 end;           // 12
        void* array[1];    // 16 (nodes follow inline)
    };
    Data* d;               // 0
};
struct QObjectList5 { QListData l; };            // QList<QObject*> == 8 bytes

// --- QObjectData (polymorphic base of QObjectPrivate; vptr at 0) -------------
struct QObjectData5 {
    void* vptr;            // 0
    void* q_ptr;           // 8
    void* parent;          // 16
    QObjectList5 children;// 24
    u32 isWidget : 1;             // 32
    u32 blockSig : 1;
    u32 wasDeleted : 1;
    u32 isDeletingChildren : 1;
    u32 sendChildEvents : 1;
    u32 receiveChildEvents : 1;
    u32 isWindow : 1;
    u32 deleteLaterCalled : 1;
    u32 unused : 24;
    i32 postedEvents;      // 36
    void* metaObjectDyn;   // 40 (QDynamicMetaObjectData*)
};                         // sizeof 48

// --- QObjectPrivate (qobject_p.h 5.15) ---------------------------------------
struct QObjectPrivate5 : QObjectData5 {
    void* extraData;       // 48
    void* threadData;      // 56
    void* connections;     // 64 (ConnectionData*)
    union {                // 72
        void* currentChildBeingDeleted;
        void* declarativeData;
    };
    void* sharedRefcount;  // 80
};                         // sizeof 88

// QObjectPrivate::ExtraData — Qt 5.15 default build (QT_NO_USERDATA *not*
// defined -> userData vector present)
struct ExtraData5 {
    void* userData;        // 0  (QVector)
    void* propertyNames;   // 8  (QList)
    void* propertyValues;  // 16 (QVector)
    void* runningTimers;   // 24 (QVector)
    void* eventFilters;    // 32 (QList)
    QString5 objectName;   // 40
};                         // sizeof 48
// Alternate build (QT_NO_USERDATA): objectName at +32
struct ExtraData5NoUserData {
    void* propertyNames;   // 0
    void* propertyValues;  // 8
    void* runningTimers;   // 16
    void* eventFilters;    // 24
    QString5 objectName;   // 32
};

// --- connections (qobject_p.h 5.15, verified verbatim) -----------------------
struct ConnectionOrSignalVector5 {
    union {
        void* nextInOrphanList;   // 0
        void* next;               // Connection*
    };
};
struct Connection5 : ConnectionOrSignalVector5 {
    void** prev;                    // 8
    void* nextConnectionList;      // 16
    void* prevConnectionList;       // 24
    void* sender;                   // 32
    void* receiver;                 // 40
    void* receiverThreadData;       // 48
    union {                         // 56
        void* callFunction;         // StaticMetaCallFunction
        void* slotObj;              // QSlotObjectBase*
    };
    void* argumentTypes;            // 64
    QAtomicInt ref_;               // 72
    u32 id;                        // 76
    u16 method_offset;             // 80
    u16 method_relative;           // 82
    i32 signal_index : 27;         // 84
    u32 connectionType : 3;        // 0 auto 1 direct 2 queued 3 blocking
    u32 isSlotObject : 1;
    u32 ownArgumentTypes : 1;
};                                 // sizeof 88
struct ConnectionList5 {
    void* first;            // 0
    void* last;             // 8
};                          // sizeof 16
struct SignalVector5 : ConnectionOrSignalVector5 {
    u64 allocated;          // 8
    // ConnectionList signals[] begins at this+1 (i.e. +16)
};                          // sizeof 16
struct Sender5 {
    void* previous;         // 0
    void* receiver;         // 8
    void* sender;           // 16
    i32 signal;             // 24
};                          // sizeof 32
struct ConnectionData5 {
    u32 currentConnectionId; // 0
    QAtomicInt ref;          // 4
    void* signalVector;      // 8  (SignalVector*)
    void* senders;           // 16 (Connection*)
    void* currentSender;     // 24 (Sender*)
    void* orphaned;          // 32 (ConnectionOrSignalVector*)
};                           // sizeof 40

// --- QMetaObject (qobjectdefs.h 5.15) ----------------------------------------
struct SuperData5 {
    const void* direct;      // 0
};
struct QMetaObject5 {
    SuperData5 superdata;            // 0
    const QArrayData* stringdata;    // 8  (array of QByteArrayData entries)
    const u32* data;                 // 16
    void* static_metacall;           // 24 (StaticMetacallFunction)
    const SuperData5* relatedMetaObjects; // 32
    void* extradata;                 // 40
};                                   // sizeof 48

// --- QMetaObjectPrivate header (qmetaobject_p.h 5.15 — 14 ints) --------------
struct QMetaObjectPrivate5 {
    i32 revision;           // 0  (8 for Qt 5.12+)
    i32 className;          // 4
    i32 classInfoCount;     // 8
    i32 classInfoData;      // 12
    i32 methodCount;        // 16
    i32 methodData;         // 20
    i32 propertyCount;      // 24
    i32 propertyData;       // 28
    i32 enumeratorCount;    // 32
    i32 enumeratorData;     // 36
    i32 constructorCount;   // 40
    i32 constructorData;    // 44
    i32 flags;              // 48
    i32 signalCount;        // 52
};                          // sizeof 56

// --- widgets (qwidget.h 5.15 — QWidgetData identical in 6.8) ------------------
struct QRectRep { i32 x1, y1, x2, y2; };        // 16
struct QWidgetData5 {
    u64 winid;              // 0  (WId)
    u32 widget_attributes;  // 8
    i32 window_flags;       // 12 (Qt::WindowFlags)
    u32 wordA;              // 16 (window_state:4|focus_policy:4|sizehint_forced:1|
                            //      is_closing:1|in_show:1|in_set_window_state:1|
                            //      fstrut_dirty:1|context_menu_policy:3|
                            //      window_modality:2|in_destructor:1|unused:13)
    u32 wordB;              // 20 (packing tail / attribute cache)
    QRectRep crect;         // 24 (x1,y1,x2,y2)
    void* pal;              // 40 (QPalette — pointer-sized stand-in)
    void* fnt;              // 48 (QFont)
    QRectRep wrect;         // 56
};                          // sizeof 72
struct QPaintDeviceRep { void* vptr; };         // 8
struct QWidget5 {
    void* vptr_qobject;     // 0  (QObject primary vtable)
    void* d_ptr;            // 8
    void* vptr_paintdevice; // 16 (secondary base vptr)
    QWidgetData5* data;     // 24
};                          // sizeof 32

// --- QtPrivate::QSlotObjectBase (lambda connections) --------------------------
struct QSlotObjectBase5 {
    void* m_impl;           // 0 (impl function ptr)
    QAtomicInt m_ref;       // 8
};                          // sizeof 16 (storage follows in concrete types)

// --- layout sanity checks (x64) ----------------------------------------------
static_assert(sizeof(QArrayData) == 24, "QArrayData x64=24");
static_assert(sizeof(QString5) == 8, "QString5 x64=8");
static_assert(offsetof(QListData::Data, array) == 16, "QList nodes at +16");
static_assert(sizeof(QObjectData5) == 48, "QObjectData x64=48");
static_assert(sizeof(QObjectPrivate5) == 88, "QObjectPrivate x64=88");
static_assert(offsetof(ExtraData5, objectName) == 40, "objectName@40 default");
static_assert(offsetof(ExtraData5NoUserData, objectName) == 32, "objectName@32 alt");
static_assert(sizeof(Connection5) == 88, "Connection x64=88");
static_assert(sizeof(ConnectionData5) == 40, "ConnectionData x64=40");
static_assert(sizeof(SignalVector5) == 16, "SignalVector x64=16");
static_assert(sizeof(ConnectionList5) == 16, "ConnectionList x64=16");
static_assert(sizeof(QMetaObject5) == 48, "QMetaObject x64=48");
static_assert(sizeof(QMetaObjectPrivate5) == 56, "QMetaObjectPrivate=56");
static_assert(offsetof(QWidgetData5, crect) == 24, "crect@24");
static_assert(offsetof(QWidgetData5, winid) == 0, "winid@0");
static_assert(offsetof(QWidget5, data) == 24, "QWidget::data@24");

} // namespace umvpqt_replica_qt5
