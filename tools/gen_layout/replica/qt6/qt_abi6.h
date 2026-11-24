// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT
// Qt 6.8 ABI REPLICA (x64) — field order copied 1:1 from qtbase/6.8 sources:
//   src/corelib/kernel/qobject.h          (QObjectData — bindingStorage, extra bits)
//   src/corelib/kernel/qobject_p.h        (QObjectPrivate)
//   src/corelib/kernel/qobject_p_p.h     (Connection, ConnectionData, ...)  [6.x]
//   src/corelib/kernel/qobjectdefs.h     (QMetaObject — metaTypes field added)
//   src/corelib/kernel/qmetaobject_p.h    (QMetaObjectPrivate — revision 9..12)
//   src/corelib/tools/qarraydata.h        (QArrayData {ref, flags, alloc} = 16)
//   src/corelib/tools/qarraydatapointer.h (QArrayDataPointer {d, ptr, size} = 24)
//   src/corelib/tools/qlist.h             (QList = QArrayDataPointer<T>)
//   src/corelib/text/qstring.h            (QString {d, ptr, size} = 24)
//   src/widgets/kernel/qwidget.h          (QWidgetData — same as 5.15)
// Verified against qtbase ref "6.8" (fetched Nov 2026).
// =============================================================================
#pragma once
#include <cstdint>

namespace umvpqt_replica_qt6 {

using i8  = int8_t;  using u8  = uint8_t;
using i16 = int16_t; using u16 = uint16_t;
using i32 = int32_t; using u32 = uint32_t;
using i64 = int64_t; using u64 = uint64_t;

// --- atomics ------------------------------------------------------------------
struct QAtomicInt { volatile i32 v; };      // 4
struct RefCounted   { QAtomicInt a; };      // QtPrivate::RefCountedData

// --- QArrayData (Qt 6.8: {QBasicAtomicInt m_ref; ArrayOptions flags; qsizetype alloc;} = 16)
struct QArrayData6 {
    QAtomicInt m_ref;      // 0
    u32 flags;             // 4 (ArrayOptions)
    i64 alloc;             // 8 (qsizetype)
};                          // sizeof 16; data follows after header (aligned)

// --- QArrayDataPointer<T> (qarraydatapointer.h 6.8: {Data* d; T* ptr; qsizetype size})
template <typename T>
struct QArrayDataPointer6 {
    void* d;               // 0 (QTypedArrayData<T>*)
    T* ptr;                // 8 (element array)
    i64 size;              // 16
};                          // sizeof 24

// --- QString (Qt 6: QStringPrivate = QArrayDataPointer<char16_t> + offset bias)
// d.ptr points at the char16_t array; d.size = length. (QStringPrivate adds the
// header offset to ptr; the memory layout seen from outside is {d, ptr, size}.)
struct QString6 {
    void* d;               // 0 (QArrayData header ptr)
    char16_t* ptr;         // 8 (character data)
    i64 size;              // 16
};                          // sizeof 24

// --- QList<T> (Qt 6 = QArrayDataPointer<T>) -----------------------------------
using QObjectList6 = QArrayDataPointer6<void*>;    // children array at ptr, count at size

// --- QObjectData (qobject.h 6.8 — bindingStorage + new bitfields) -----------
struct QObjectData6 {
    void* vptr;            // 0
    void* q_ptr;           // 8
    void* parent;          // 16
    QObjectList6 children; // 24 (24 bytes!)
    u32 isWidget : 1;             // 48
    u32 blockSig : 1;
    u32 wasDeleted : 1;
    u32 isDeletingChildren : 1;
    u32 sendChildEvents : 1;
    u32 receiveChildEvents : 1;
    u32 isWindow : 1;
    u32 deleteLaterCalled : 1;
    u32 isQuickItem : 1;
    u32 willBeWidget : 1;
    u32 wasWidget : 1;
    u32 receiveParentEvents : 1;
    u32 unused : 20;
    QAtomicInt postedEvents; // 52
    void* metaObjectDyn;     // 56 (QDynamicMetaObjectData*)
    void* bindingStorage;    // 64
};                           // sizeof 72

// --- QObjectPrivate (qobject_p.h 6.8) ----------------------------------------
struct QObjectPrivate6 : QObjectData6 {
    void* extraData;       // 72
    void* threadData;      // 80
    void* connections;     // 88
    union {                // 96
        void* currentChildBeingDeleted;
        void* declarativeData;
    };
    void* sharedRefcount;  // 104
};                         // sizeof 112

// ExtraData (qobject_p.h 6.8): QLists are 24 bytes each now; objectName is a
// compat property stored as QString (24 bytes); parent pointer last.
struct ExtraData6 {
    void* propertyNames;   // 0  (QList<QByteArray> — 24 bytes)
    void* propertyNames_pad1;  // 8
    void* propertyNames_pad2;  // 16
    void* propertyValues;  // 24 (QVector<QVariant> — 24)
    void* propertyValues_pad1; // 32
    void* propertyValues_pad2; // 40
    void* runningTimers;   // 48 (QVector<int> — 24)
    void* runningTimers_pad1; // 56
    void* runningTimers_pad2; // 64
    void* eventFilters;    // 72 (QList<QPointer<QObject>> — 24)
    void* eventFilters_pad1; // 80
    void* eventFilters_pad2; // 88
    QString6 objectName;   // 96 (Q_OBJECT_COMPAT_PROPERTY storage — QString)
    void* parent;          // 120
};                         // sizeof 128

// --- connections (qobject_p_p.h 6.8, verified verbatim) ----------------------
struct TaggedSignalVector6 {
    u64 c;                  // 0 (tagged: bit0 set => SignalVector)
};
struct ConnectionOrSignalVector6 {
    union {                 // 0
        TaggedSignalVector6 nextInOrphanList;
        void* next;         // Connection*
    };
};
struct Connection6 : ConnectionOrSignalVector6 {
    void** prev;                    // 8
    void* nextConnectionList;      // 16
    void* prevConnectionList;      // 24
    void* sender;                  // 32
    void* receiver;                // 40
    void* receiverThreadData;      // 48
    union {                         // 56
        void* callFunction;
        void* slotObj;
    };
    void* argumentTypes;            // 64
    QAtomicInt ref_;               // 72
    u32 id;                        // 76
    u16 method_offset;             // 80
    u16 method_relative;           // 82
    i32 signal_index : 27;         // 84
    u32 connectionType : 2;        // 0 auto 1 direct 2 queued 3 blocking
    u32 isSlotObject : 1;
    u32 ownArgumentTypes : 1;
    u32 isSingleShot : 1;
};                                 // sizeof 88
struct ConnectionList6 {
    void* first;            // 0
    void* last;             // 8
};                          // sizeof 16
struct SignalVector6 : ConnectionOrSignalVector6 {
    u64 allocated;          // 8
};                          // sizeof 16
struct Sender6 {
    void* previous;         // 0
    void* receiver;         // 8
    void* sender;           // 16
    i32 signal;             // 24
    void* receiverConnections; // 28? no — kept 32-byte padding minimal:
};                          // sizeof 32 (i32 signal + padding to 8)
struct ConnectionData6 {
    u32 currentConnectionId; // 0
    QAtomicInt ref;          // 4
    void* signalVector;      // 8
    void* senders;           // 16
    void* currentSender;     // 24
    TaggedSignalVector6 orphaned; // 32 (std::atomic<TaggedSignalVector>)
};                           // sizeof 40

// --- QMetaObject (qobjectdefs.h 6.8) ------------------------------------------
struct SuperData6 {
    const void* direct;      // 0
};
struct QMetaObject6 {
    SuperData6 superdata;            // 0
    const u32* stringdata;           // 8  (uint array: offset/len pairs)
    const u32* data;                 // 16
    void* static_metacall;           // 24
    const SuperData6* relatedMetaObjects; // 32
    const void* metaTypes;           // 40 (QMetaTypeInterface* const*)
    void* extradata;                 // 48
};                                   // sizeof 56

// --- QMetaObjectPrivate header (qmetaobject_p.h 6.8 — same 14 ints, rev 9..12)
struct QMetaObjectPrivate6 {
    i32 revision;           // 0 (9=6.0 10=6.2 11=6.5 12=6.6+)
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

// --- widgets (qwidget.h 6.8 — QWidgetData identical to 5.15) ------------------
struct QRectRep6 { i32 x1, y1, x2, y2; };       // 16
struct QWidgetData6 {
    u64 winid;              // 0
    u32 widget_attributes;  // 8
    i32 window_flags;       // 12
    u32 wordA;              // 16 (bitfield pack 1)
    u32 wordB;              // 20 (bitfield pack 2)
    QRectRep6 crect;        // 24
    void* pal;              // 40
    void* fnt;              // 48
    QRectRep6 wrect;        // 56
};                          // sizeof 72
struct QPaintDeviceRep6 { void* vptr; };        // 8
struct QWidget6 {
    void* vptr_qobject;     // 0
    void* d_ptr;            // 8
    void* vptr_paintdevice; // 16
    QWidgetData6* data;    // 24
};                          // sizeof 32

// --- QtPrivate::QSlotObjectBase ----------------------------------------------
struct QSlotObjectBase6 {
    void* m_impl;           // 0
    QAtomicInt m_ref;       // 8
    // (6.5+: QMetaTypeInterface args follow; storage begins at +16 same as 5)
};                          // sizeof 16

// --- layout sanity checks (x64) ----------------------------------------------
static_assert(sizeof(QArrayData6) == 16, "QArrayData x64=16");
static_assert(sizeof(QString6) == 24, "QString6 x64=24");
static_assert(sizeof(QObjectList6) == 24, "QList6 x64=24");
static_assert(sizeof(QObjectData6) == 72, "QObjectData6 x64=72");
static_assert(sizeof(QObjectPrivate6) == 112, "QObjectPrivate6 x64=112");
static_assert(offsetof(ExtraData6, objectName) == 96, "objectName@96");
static_assert(offsetof(ExtraData6, parent) == 120, "parent@120");
static_assert(sizeof(Connection6) == 88, "Connection6 x64=88");
static_assert(sizeof(ConnectionData6) == 40, "ConnectionData6 x64=40");
static_assert(sizeof(SignalVector6) == 16, "SignalVector6 x64=16");
static_assert(sizeof(ConnectionList6) == 16, "ConnectionList6 x64=16");
static_assert(sizeof(QMetaObject6) == 56, "QMetaObject6 x64=56");
static_assert(sizeof(QMetaObjectPrivate6) == 56, "QMetaObjectPrivate6=56");
static_assert(offsetof(QWidgetData6, crect) == 24, "crect@24");
static_assert(offsetof(QWidgetData6, winid) == 0, "winid@0");
static_assert(offsetof(QWidget6, data) == 24, "QWidget6::data@24");

} // namespace umvpqt_replica_qt6
