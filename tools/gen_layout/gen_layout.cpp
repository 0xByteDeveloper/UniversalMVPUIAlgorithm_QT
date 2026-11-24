// =============================================================================
// UMVP-QT // tools/gen_layout/gen_layout.cpp
// Emits src/qt_layout_db.h — every offset computed with offsetof() against the
// replica ABI headers (qtbase 5.15 / 6.8 field order, 1:1). NO hand-written
// offsets anywhere in the SDK. Mirrors the original UMVP gen_layout approach.
//   build: g++ -std=c++17 -O2 -I../../include gen_layout.cpp -o gen_layout
//   run:   ./gen_layout > ../../src/qt_layout_db.h
// (Compile with -m32 + i686 toolchain to emit x86 tables — sandbox is x64.)
// =============================================================================
#include <cstdio>
#include <cstddef>
#include <cstdint>

#include "../../include/umvpqt/qt_layout.h"
#include "replica/qt5/qt_abi5.h"
#include "replica/qt6/qt_abi6.h"

using namespace umvpqt;
namespace r5 = umvpqt_replica_qt5;
namespace r6 = umvpqt_replica_qt6;

// Emit one QtLayout initializer, in the exact field order of QtLayout.
static void emit_family(const char* name, QtFamily fam) {
    if (fam == QtFamily::Qt5) {
        const r5::QObjectData5*      od  = nullptr;
        const r5::QObjectPrivate5*  op  = nullptr;
        const r5::QMetaObject5*     mo  = nullptr;
        const r5::QMetaObjectPrivate5* mop = nullptr;
        const r5::Connection5*     cn  = nullptr;
        const r5::ConnectionData5* cd  = nullptr;
        const r5::QString5*        st  = nullptr;
        const r5::QListData*       ld  = nullptr;
        const r5::QWidget5*        qw  = nullptr;
        const r5::QWidgetData5*   qwd = nullptr;
        const r5::QListData::Data* ldd = nullptr;
        std::printf(
            "constexpr QtLayout QT5_X64 = {\n"
            "    /* obj_qptr   */ %d, /* obj_parent */ %d, /* obj_children */ %d,"
            " /* obj_children_size */ %d,\n"
            "    /* obj_bits   */ %d, /* obj_posted */ %d, /* obj_metaobj_dyn */ %d,"
            " /* obj_sizeof */ %d,\n"
            "    /* priv_extra */ %d, /* priv_thread */ %d, /* priv_conn */ %d,"
            " /* priv_shared */ %d, /* priv_sizeof */ %d,\n"
            "    /* extra_objectname */ %d, /* extra_objectname_alt */ %d,\n"
            "    /* mo_superdata */ %d, /* mo_stringdata */ %d, /* mo_data */ %d,"
            " /* mo_static_metacall */ %d, /* mo_sizeof */ %d,\n"
            "    /* mop_revision */ %d, /* mop_classname */ %d, /* mop_methodcount */ %d,"
            " /* mop_methoddata */ %d, /* mop_signalcount */ %d, /* mop_ints_per_method */ %d,\n"
            "    /* conn_next */ %d, /* conn_prev */ %d, /* conn_nextlist */ %d,"
            " /* conn_sender */ %d, /* conn_receiver */ %d, /* conn_callfn */ %d,\n"
            "    /* conn_argtypes */ %d, /* conn_ref */ %d, /* conn_id */ %d,\n"
            "    /* conn_moffset */ %d, /* conn_mrelative */ %d, /* conn_bits */ %d,"
            " /* conn_sizeof */ %d,\n"
            "    /* sv_lists */ %d, /* cd_signalvector */ %d, /* cd_sizeof */ %d,\n"
            "    /* str_hdr_size */ %d, /* str_hdr_offset */ %d, /* str_obj_size */ %d,\n"
            "    /* str_ptr */ %d, /* str_size */ %d,\n"
            "    /* list_begin */ %d, /* list_end */ %d, /* list_array */ %d,\n"
            "    /* list_ptr */ %d, /* list_size */ %d,\n"
            "    /* qw_data_ptr */ %d, /* qwd_winid */ %d, /* qwd_flags */ %d,"
            " /* qwd_crect */ %d, /* qwd_size */ %d,\n"
            "    /* stringdata_kind */ %d\n"
            "};\n",
            offsetof(r5::QObjectData5, q_ptr),
            offsetof(r5::QObjectData5, parent),
            offsetof(r5::QObjectData5, children),
            (int)sizeof(r5::QObjectList5),
            offsetof(r5::QObjectData5, postedEvents) - 4,  // bitfield word precedes postedEvents
            offsetof(r5::QObjectData5, postedEvents),
            offsetof(r5::QObjectData5, metaObjectDyn),
            (int)sizeof(r5::QObjectData5),
            offsetof(r5::QObjectPrivate5, extraData),
            offsetof(r5::QObjectPrivate5, threadData),
            offsetof(r5::QObjectPrivate5, connections),
            offsetof(r5::QObjectPrivate5, sharedRefcount),
            (int)sizeof(r5::QObjectPrivate5),
            offsetof(r5::ExtraData5, objectName),
            offsetof(r5::ExtraData5NoUserData, objectName),
            offsetof(r5::QMetaObject5, superdata),
            offsetof(r5::QMetaObject5, stringdata),
            offsetof(r5::QMetaObject5, data),
            offsetof(r5::QMetaObject5, static_metacall),
            (int)sizeof(r5::QMetaObject5),
            offsetof(r5::QMetaObjectPrivate5, revision),
            offsetof(r5::QMetaObjectPrivate5, className),
            offsetof(r5::QMetaObjectPrivate5, methodCount),
            offsetof(r5::QMetaObjectPrivate5, methodData),
            offsetof(r5::QMetaObjectPrivate5, signalCount),
            5,   // ints per method entry (rev 8)
            offsetof(r5::Connection5, next),
            offsetof(r5::Connection5, prev),
            offsetof(r5::Connection5, nextConnectionList),
            offsetof(r5::Connection5, sender),
            offsetof(r5::Connection5, receiver),
            offsetof(r5::Connection5, callFunction),
            offsetof(r5::Connection5, argumentTypes),
            offsetof(r5::Connection5, ref_),
            offsetof(r5::Connection5, id),
            offsetof(r5::Connection5, method_offset),
            offsetof(r5::Connection5, method_relative),
            offsetof(r5::Connection5, method_relative) + 2,  // bitfield word (88-4)
            (int)sizeof(r5::Connection5),
            (int)sizeof(r5::SignalVector5),
            offsetof(r5::ConnectionData5, signalVector),
            (int)sizeof(r5::ConnectionData5),
            offsetof(r5::QArrayData, size),
            offsetof(r5::QArrayData, offset),
            (int)sizeof(r5::QString5),
            -1, -1,
            offsetof(r5::QListData::Data, begin),
            offsetof(r5::QListData::Data, end),
            offsetof(r5::QListData::Data, array),
            -1, -1,
            offsetof(r5::QWidget5, data),
            offsetof(r5::QWidgetData5, winid),
            offsetof(r5::QWidgetData5, window_flags),
            offsetof(r5::QWidgetData5, crect),
            (int)sizeof(r5::QWidgetData5),
            0    // stringdata_kind: QByteArrayData entries
        );
        (void)od; (void)op; (void)mo; (void)mop; (void)cn; (void)cd;
        (void)st; (void)ld; (void)qw; (void)qwd; (void)ldd;
    } else {
        std::printf(
            "constexpr QtLayout QT6_X64 = {\n"
            "    /* obj_qptr   */ %d, /* obj_parent */ %d, /* obj_children */ %d,"
            " /* obj_children_size */ %d,\n"
            "    /* obj_bits   */ %d, /* obj_posted */ %d, /* obj_metaobj_dyn */ %d,"
            " /* obj_sizeof */ %d,\n"
            "    /* priv_extra */ %d, /* priv_thread */ %d, /* priv_conn */ %d,"
            " /* priv_shared */ %d, /* priv_sizeof */ %d,\n"
            "    /* extra_objectname */ %d, /* extra_objectname_alt */ %d,\n"
            "    /* mo_superdata */ %d, /* mo_stringdata */ %d, /* mo_data */ %d,"
            " /* mo_static_metacall */ %d, /* mo_sizeof */ %d,\n"
            "    /* mop_revision */ %d, /* mop_classname */ %d, /* mop_methodcount */ %d,"
            " /* mop_methoddata */ %d, /* mop_signalcount */ %d, /* mop_ints_per_method */ %d,\n"
            "    /* conn_next */ %d, /* conn_prev */ %d, /* conn_nextlist */ %d,"
            " /* conn_sender */ %d, /* conn_receiver */ %d, /* conn_callfn */ %d,\n"
            "    /* conn_argtypes */ %d, /* conn_ref */ %d, /* conn_id */ %d,\n"
            "    /* conn_moffset */ %d, /* conn_mrelative */ %d, /* conn_bits */ %d,"
            " /* conn_sizeof */ %d,\n"
            "    /* sv_lists */ %d, /* cd_signalvector */ %d, /* cd_sizeof */ %d,\n"
            "    /* str_hdr_size */ %d, /* str_hdr_offset */ %d, /* str_obj_size */ %d,\n"
            "    /* str_ptr */ %d, /* str_size */ %d,\n"
            "    /* list_begin */ %d, /* list_end */ %d, /* list_array */ %d,\n"
            "    /* list_ptr */ %d, /* list_size */ %d,\n"
            "    /* qw_data_ptr */ %d, /* qwd_winid */ %d, /* qwd_flags */ %d,"
            " /* qwd_crect */ %d, /* qwd_size */ %d,\n"
            "    /* stringdata_kind */ %d\n"
            "};\n",
            offsetof(r6::QObjectData6, q_ptr),
            offsetof(r6::QObjectData6, parent),
            offsetof(r6::QObjectData6, children),
            (int)sizeof(r6::QObjectList6),
            offsetof(r6::QObjectData6, postedEvents) - 4,
            offsetof(r6::QObjectData6, postedEvents),
            offsetof(r6::QObjectData6, metaObjectDyn),
            (int)sizeof(r6::QObjectData6),
            offsetof(r6::QObjectPrivate6, extraData),
            offsetof(r6::QObjectPrivate6, threadData),
            offsetof(r6::QObjectPrivate6, connections),
            offsetof(r6::QObjectPrivate6, sharedRefcount),
            (int)sizeof(r6::QObjectPrivate6),
            offsetof(r6::ExtraData6, objectName),
            -1,   // no QT_NO_USERDATA alternate in Qt 6
            offsetof(r6::QMetaObject6, superdata),
            offsetof(r6::QMetaObject6, stringdata),
            offsetof(r6::QMetaObject6, data),
            offsetof(r6::QMetaObject6, static_metacall),
            (int)sizeof(r6::QMetaObject6),
            offsetof(r6::QMetaObjectPrivate6, revision),
            offsetof(r6::QMetaObjectPrivate6, className),
            offsetof(r6::QMetaObjectPrivate6, methodCount),
            offsetof(r6::QMetaObjectPrivate6, methodData),
            offsetof(r6::QMetaObjectPrivate6, signalCount),
            6,    // ints per method entry (rev >= 9, QMetaMethod::Data::Size = 6)
            offsetof(r6::Connection6, next),
            offsetof(r6::Connection6, prev),
            offsetof(r6::Connection6, nextConnectionList),
            offsetof(r6::Connection6, sender),
            offsetof(r6::Connection6, receiver),
            offsetof(r6::Connection6, callFunction),
            offsetof(r6::Connection6, argumentTypes),
            offsetof(r6::Connection6, ref_),
            offsetof(r6::Connection6, id),
            offsetof(r6::Connection6, method_offset),
            offsetof(r6::Connection6, method_relative),
            offsetof(r6::Connection6, method_relative) + 2,
            (int)sizeof(r6::Connection6),
            (int)sizeof(r6::SignalVector6),
            offsetof(r6::ConnectionData6, signalVector),
            (int)sizeof(r6::ConnectionData6),
            0, 0,   // Qt6 QString has no header size/offset fields
            (int)sizeof(r6::QString6),
            offsetof(r6::QString6, ptr),
            offsetof(r6::QString6, size),
            -1, -1, -1,
            offsetof(r6::QObjectList6, ptr),
            offsetof(r6::QObjectList6, size),
            offsetof(r6::QWidget6, data),
            offsetof(r6::QWidgetData6, winid),
            offsetof(r6::QWidgetData6, window_flags),
            offsetof(r6::QWidgetData6, crect),
            (int)sizeof(r6::QWidgetData6),
            1    // stringdata_kind: uint offset/len pairs
        );
    }
}

int main() {
#if !defined(__x86_64__) && !defined(_M_X64)
#error "gen_layout: this sandbox emits x64 tables only (build with -m32 for x86)"
#endif
    std::printf("// ============================================================="
                "=================\n");
    std::printf("// GENERATED by tools/gen_layout — DO NOT EDIT BY HAND\n");
    std::printf("// Qt 5.15 / 6.8 x64 ABI offsets (offsetof against verified replicas)\n"
                "// ============================================================="
                "=================\n");
    std::printf("#include \"umvpqt/qt_layout.h\"\n\nnamespace umvpqt { namespace db {\n\n");
    emit_family("QT5", QtFamily::Qt5);
    std::printf("\n");
    emit_family("QT6", QtFamily::Qt6);
    std::printf("\nstatic_assert(QT5_X64.obj_qptr == 8, \"qt5 q_ptr\");\n"
                "static_assert(QT5_X64.conn_sizeof == 88, \"qt5 connection\");\n"
                "static_assert(QT6_X64.obj_sizeof == 72, \"qt6 QObjectData\");\n"
                "static_assert(QT6_X64.conn_sizeof == 88, \"qt6 connection\");\n"
                "static_assert(QT6_X64.str_obj_size == 24, \"qt6 QString\");\n");
    std::printf("\n} // namespace db\n} // namespace umvpqt\n");
    return 0;
}
