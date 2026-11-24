// =============================================================================
// UMVP-QT // tests/test_layout.cpp — layout DB vs replica offsetof integrity.
// The DB is generated from the same replicas, so this test guards accidental
// regeneration failures and struct drift (field order edits, padding bugs).
// PASS criteria: every critical offset matches a freshly computed offsetof AND
// QString/QList decoding constants match the family semantics.
// =============================================================================
#include <cstdio>
#include <cstddef>

#include "qt_layout_db.h"
#include "umvpqt/qt_layout.h"
#include "../tools/gen_layout/replica/qt5/qt_abi5.h"
#include "../tools/gen_layout/replica/qt6/qt_abi6.h"

using namespace umvpqt;
namespace r5 = umvpqt_replica_qt5;
namespace r6 = umvpqt_replica_qt6;

static int failures = 0;
static int checks = 0;

template <typename T>
void expect(const char* what, T got, T want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("FAIL %s: got %lld want %lld\n", what, (long long)got, (long long)want);
    }
}

int main() {
    const QtLayout& q5 = db::QT5_X64;
    const QtLayout& q6 = db::QT6_X64;

    // ---- Qt 5.15 x64 ----
    expect("qt5 obj_qptr", (long long)q5.obj_qptr, (long long)offsetof(r5::QObjectData5, q_ptr));
    expect("qt5 obj_parent", (long long)q5.obj_parent, (long long)offsetof(r5::QObjectData5, parent));
    expect("qt5 obj_children", (long long)q5.obj_children, (long long)offsetof(r5::QObjectData5, children));
    expect("qt5 obj_bits", (long long)q5.obj_bits, 32LL);
    expect("qt5 obj_sizeof", (long long)q5.obj_sizeof, (long long)sizeof(r5::QObjectData5));
    expect("qt5 priv_conn", (long long)q5.priv_conn, (long long)offsetof(r5::QObjectPrivate5, connections));
    expect("qt5 extra_objectname", (long long)q5.extra_objectname, (long long)offsetof(r5::ExtraData5, objectName));
    expect("qt5 extra_objectname_alt", (long long)q5.extra_objectname_alt, 32LL);
    expect("qt5 mo_static_metacall", (long long)q5.mo_static_metacall, (long long)offsetof(r5::QMetaObject5, static_metacall));
    expect("qt5 conn_callfn", (long long)q5.conn_callfn, 56LL);
    expect("qt5 conn_bits", (long long)q5.conn_bits, 84LL);
    expect("qt5 conn_sizeof", (long long)q5.conn_sizeof, (long long)sizeof(r5::Connection5));
    expect("qt5 sv_lists", (long long)q5.sv_lists, (long long)sizeof(r5::SignalVector5));
    expect("qt5 cd_signalvector", (long long)q5.cd_signalvector, (long long)offsetof(r5::ConnectionData5, signalVector));
    expect("qt5 str_obj_size", (long long)q5.str_obj_size, 8LL);
    expect("qt5 stringdata_kind", (long long)q5.stringdata_kind, 0LL);
    expect("qt5 ints_per_method", (long long)q5.mop_ints_per_method, 5LL);
    expect("qt5 qwd_crect", (long long)q5.qwd_crect, (long long)offsetof(r5::QWidgetData5, crect));
    expect("qt5 list_array", (long long)q5.list_array, 16LL);
    expect("qt5 list_ptr", (long long)q5.list_ptr, -1LL);

    // ---- Qt 6.8 x64 ----
    expect("qt6 obj_children", (long long)q6.obj_children, (long long)offsetof(r6::QObjectData6, children));
    expect("qt6 obj_children_size", (long long)q6.obj_children_size, 24LL);
    expect("qt6 obj_bits", (long long)q6.obj_bits, 48LL);
    expect("qt6 obj_sizeof", (long long)q6.obj_sizeof, (long long)sizeof(r6::QObjectData6));
    expect("qt6 priv_extra", (long long)q6.priv_extra, (long long)offsetof(r6::QObjectPrivate6, extraData));
    expect("qt6 priv_conn", (long long)q6.priv_conn, (long long)offsetof(r6::QObjectPrivate6, connections));
    expect("qt6 extra_objectname", (long long)q6.extra_objectname, (long long)offsetof(r6::ExtraData6, objectName));
    expect("qt6 extra_objectname_alt", (long long)q6.extra_objectname_alt, -1LL);
    expect("qt6 mo_sizeof", (long long)q6.mo_sizeof, (long long)sizeof(r6::QMetaObject6));
    expect("qt6 conn_sizeof", (long long)q6.conn_sizeof, (long long)sizeof(r6::Connection6));
    expect("qt6 conn_bits", (long long)q6.conn_bits, 84LL);
    expect("qt6 str_obj_size", (long long)q6.str_obj_size, 24LL);
    expect("qt6 str_ptr", (long long)q6.str_ptr, 8LL);
    expect("qt6 str_size", (long long)q6.str_size, 16LL);
    expect("qt6 stringdata_kind", (long long)q6.stringdata_kind, 1LL);
    expect("qt6 ints_per_method", (long long)q6.mop_ints_per_method, 6LL);
    expect("qt6 list_ptr", (long long)q6.list_ptr, 8LL);
    expect("qt6 list_size", (long long)q6.list_size, 16LL);
    expect("qt6 list_array", (long long)q6.list_array, -1LL);
    expect("qt6 qwd_crect", (long long)q6.qwd_crect, (long long)offsetof(r6::QWidgetData6, crect));

    std::printf("[%s] test_layout: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
