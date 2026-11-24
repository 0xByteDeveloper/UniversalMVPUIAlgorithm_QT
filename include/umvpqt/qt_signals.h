// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/qt_signals.h
// Connection graph scanner:
//   QObjectPrivate::connections -> ConnectionData -> signalVector ->
//   ConnectionList[i] -> Connection chain.
// For every connection: sender/receiver/absolute signal index/local method,
// connection type, isSlotObject; names resolved through the meta chains;
// HANDLER code address resolved either via the slot-object storage or via
// DEEP DISASSEMBLY of the receiver's qt_static_metacall switch.
// Layouts verified against qtbase 5.15 qobject_p.h and 6.8 qobject_p_p.h.
// =============================================================================
#pragma once
#include <optional>
#include <string>
#include <vector>

#include "process.h"
#include "qt_layout.h"
#include "qt_meta.h"
#include "qt_scan.h"
#include "types.h"

namespace umvpqt {

class ConnectionScanner {
public:
    ConnectionScanner(IProcessReader& r, const QtLayout& L)
        : r_(r), L_(L), mr_(r, L) {}

    // All connections where `o` is the SENDER (its outgoing signals).
    std::vector<ConnectionInfo> outgoing(const DiscoveredObject& o);

    // Resolve the actual handler function of a connection (slot body).
    std::optional<HandlerInfo> resolveHandler(const ConnectionInfo& ci,
                                             const DiscoveredObject& receiver);

    // Emit a signal the way QMetaObject::activate does (direct part):
    // walks the connection list and calls each direct connection's
    // callFunction(receiver, InvokeMetaMethod, localIdx, argv).
    // Used by the invoke engine's god-mode signal emission.
    struct EmitStats { int fired = 0, queued = 0, skipped = 0; };

    // low-level struct accessors (shared with invoke engine)
    Address connectionDataOf(const DiscoveredObject& o) const;

private:
    IProcessReader& r_;
    const QtLayout& L_;
    MetaObjectReader mr_;
};

} // namespace umvpqt
