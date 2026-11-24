// =============================================================================
// UMVP-QT // src/qt_signals.cpp — connection graph walk + handler resolution.
// Qt 5.15 / 6.8 Connection layout (identical offsets, different bitfield pack):
//   +0  next / nextInOrphanList (union)
//   +8  prev                    +16 nextConnectionList   +24 prevConnectionList
//   +32 sender                  +40 receiver            +48 receiverThreadData
//   +56 callFunction / slotObj  +64 argumentTypes      +72 ref_ +76 id
//   +80 method_offset:16         +82 method_relative:16
//   +84 bits: signal_index:27 | connectionType (3 bits Qt5 / 2 bits Qt6)
//            | isSlotObject | ownArgumentTypes (| isSingleShot Qt6)
// SignalVector { +0 union, +8 allocated(u64) }; ConnectionList[] at sv+16,
//   list for signal i at sv + 16 + 16*(i+1);  list(-1) (allsignals) at sv+16.
// =============================================================================
#include "umvpqt/qt_signals.h"
#include "umvpqt/disasm.h"

#include <cstring>

namespace umvpqt {

namespace {
int connectionTypeBits(const QtLayout& L) { return L.stringdata_kind == 0 ? 3 : 2; }
} // namespace

Address ConnectionScanner::connectionDataOf(const DiscoveredObject& o) const {
    if (!o.d_ptr) return 0;
    return r_.readPtr(o.d_ptr + L_.priv_conn);
}

std::vector<ConnectionInfo> ConnectionScanner::outgoing(const DiscoveredObject& o) {
    std::vector<ConnectionInfo> out;
    Address cd = connectionDataOf(o);
    if (!cd || !r_.isReadable(cd)) return out;
    Address sv = r_.readPtr(cd + L_.cd_signalvector);
    if (!sv || !r_.isReadable(sv)) return out;
    uint64_t allocated = 0;
    if (!r_.readU64(sv + 8, &allocated)) return out;
    if (allocated > 4096) allocated = 4096;   // defensive

    // bitfield decode constants
    const int typeBits = connectionTypeBits(L_);
    const int slotObjShift = 27 + typeBits;

    const size_t totalLimit = 4096;
    size_t total = 0;
    for (int64_t sig = -1; sig < (int64_t)allocated && total < totalLimit; ++sig) {
        // list for signal i at sv + 16 + 16*(i+1); i = -1 -> sv+16
        Address listAddr = sv + L_.sv_lists + (Address)(sig + 1) * 16;
        Address first = r_.readPtr(listAddr);
        Address c = first;
        for (int hop = 0; c && hop < 1024 && total < totalLimit; ++hop, ++total) {
            if (!r_.isReadable(c)) break;
            uint8_t raw[96] = {0};
            if (!r_.read(c, raw, L_.conn_sizeof > 96 ? 96 : L_.conn_sizeof)) break;
            auto rd64 = [&](int off) -> uint64_t {
                uint64_t v = 0;
                memcpy(&v, raw + off, 8);
                return v;
            };
            uint16_t moffset = 0, mrelative = 0;
            memcpy(&moffset, raw + L_.conn_moffset, 2);
            memcpy(&mrelative, raw + L_.conn_mrelative, 2);
            uint32_t bits = 0;
            memcpy(&bits, raw + L_.conn_bits, 4);

            ConnectionInfo ci;
            ci.connection = c;
            ci.sender = (Address)rd64(L_.conn_sender);
            ci.receiver = (Address)rd64(L_.conn_receiver);
            ci.signalIndex = (int32_t)(bits & 0x07FFFFFF);
            int ctype = (bits >> 27) & ((1 << typeBits) - 1);
            ci.isSlotObject = (bits >> slotObjShift) & 1;
            ci.slotMethodIndex = (int)moffset + (int)mrelative;
            uint64_t callfn = rd64(L_.conn_callfn);
            ci.callFunction = (Address)callfn;
            ci.slotObject = ci.isSlotObject ? (Address)callfn : 0;
            ci.id = *(uint32_t*)(raw + L_.conn_id);
            switch (ctype) {
            case 1: ci.connectionType = "direct"; break;
            case 2: ci.connectionType = "queued"; break;
            case 3: ci.connectionType = "blocking"; break;
            default: ci.connectionType = "auto"; break;
            }

            // resolve names
            Address owner = 0;
            int localIdx = -1;
            auto sigm = mr_.resolveSignalByAbsIndex(o.metaObject, ci.signalIndex,
                                                     &owner, &localIdx);
            if (sigm) {
                ci.signalName = sigm->name;
                ci.signalOwnerClass = sigm->ownerClass;
            }
            if (ci.receiver && !ci.isSlotObject && r_.isReadable(ci.receiver)) {
                // receiver metaobject via vtable thunk (god path, no PDB);
                // functor connections have no method index to resolve
                Address rvtable = r_.readPtr(ci.receiver);
                if (rvtable && r_.isExecutable(rvtable)) {
                    Address thunk = r_.readPtr(rvtable + 16);
                    Address rmeta = thunk ? resolve_metaobject_thunk(r_, thunk) : 0;
                    if (rmeta && r_.isReadable(rmeta)) {
                        Address slotOwner = 0;
                        int slotLocal = -1;
                        if (mr_.resolveMethodByAbsIndex(rmeta, ci.slotMethodIndex,
                                                         &slotOwner, &slotLocal)) {
                            // method entry of slotOwner at local index
                            auto cls = mr_.parseMetaClass(slotOwner);
                            if (cls && slotLocal < (int)cls->methods.size()) {
                                ci.slotName = cls->methods[(size_t)slotLocal].name;
                                ci.slotOwnerClass = cls->methods[(size_t)slotLocal].ownerClass;
                            }
                        }
                    }
                }
            }
            out.push_back(ci);
            c = (Address)rd64(L_.conn_nextlist);
        }
    }
    return out;
}

std::optional<HandlerInfo> ConnectionScanner::resolveHandler(
    const ConnectionInfo& ci, const DiscoveredObject& receiver) {
    if (!ci.receiver) return std::nullopt;
    HandlerInfo h;

    if (ci.isSlotObject && ci.slotObject) {
        // functor connection: QSlotObjectBase { m_impl, m_ref, storage@+16 }
        // storage = pointer-to-member-function {fn, adjustment}
        Address fn = r_.readPtr(ci.slotObject + 16);
        if (!fn || !r_.isExecutable(fn)) return std::nullopt;
        h.ownerClass = ci.slotOwnerClass.empty() ? "?" : ci.slotOwnerClass;
        h.methodName = ci.slotName.empty() ? "<functor>" : ci.slotName;
        h.entry = fn;
        h.via = ci.slotObject;
        h.viaKind = "slot-object";
        h.confidence = 95;
    } else {
        // method connection: callFunction = receiver class qt_static_metacall.
        // DEEP DISASSEMBLY: solve the switch -> case(method_relative) -> call.
        Address fn = ci.callFunction;
        if (!fn || !r_.isExecutable(fn)) {
            // fallback: receiver metaobject's static_metacall field
            fn = r_.readPtr(receiver.metaObject + L_.mo_static_metacall);
            if (!fn || !r_.isExecutable(fn)) return std::nullopt;
        }
        MetacallSolve sol = solve_metacall(r_, fn);
        Address handler = 0;
        bool inlined = false;
        for (const MetacallCase& mc : sol.cases)
            if (mc.localIndex == ci.slotMethodIndex - (int)mr_.methodOffset(receiver.metaObject)) {
                handler = mc.handler;
                inlined = mc.handler && mc.handler == mc.caseTarget;
            }
        if (!handler) {
            // try direct local index too (defensive)
            for (const MetacallCase& mc : sol.cases)
                if (mc.localIndex == ci.slotMethodIndex && mc.handler) handler = mc.handler;
        }
        if (!handler) return std::nullopt;
        h.ownerClass = ci.slotOwnerClass.empty() ? receiver.className : ci.slotOwnerClass;
        h.methodName = ci.slotName.empty() ? ("slot#" + std::to_string(ci.slotMethodIndex))
                                          : ci.slotName;
        h.entry = handler;
        h.via = fn;
        h.viaKind = inlined ? "qt_static_metacall-inlined" : "qt_static_metacall";
        h.confidence = inlined ? 80 : 90;
    }

    // code range [base,end)
    h.base = h.entry;
    h.end = function_end(r_, h.entry);
    h.disasm = disassemble_range(r_, h.base, h.end);
    return h;
}

} // namespace umvpqt
