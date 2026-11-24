// =============================================================================
// UMVP-QT // src/qt_invoke.cpp — invoke engine implementation.
// Local/mock path: executor calls the resolved static_metacall in-process.
// Windows path (compiled under _WIN32): CreateRemoteThread + position
// independent shellcode that performs the (up to) 5-argument call inside the
// target, plus scratch buffers via VirtualAllocEx.
// QMetaObject::Call numbering (both Qt5/Qt6): InvokeMetaMethod=0,
// ReadProperty=1.
// =============================================================================
#include "umvpqt/qt_invoke.h"
#include "umvpqt/disasm.h"

#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace umvpqt {

Address InvokeEngine::receiverMetaObject(Address receiverObject) {
    if (!receiverObject || !r_.isReadable(receiverObject)) return 0;
    Address vtable = r_.readPtr(receiverObject);
    if (!vtable || !r_.isExecutable(vtable)) return 0;
    Address thunk = r_.readPtr(vtable + 16);
    if (!thunk || !r_.isExecutable(thunk)) return 0;
    return resolve_metaobject_thunk(r_, thunk);
}

std::optional<MetaMethod> InvokeEngine::findOwnerMethod(const DiscoveredObject& obj,
                                                        const std::string& name,
                                                        MetaMethodType type) {
    for (Address mo : mr_.metaChain(obj.metaObject)) {
        auto cls = mr_.parseMetaClass(mo);
        if (!cls) continue;
        for (const MetaMethod& m : cls->methods)
            if (m.name == name && (type == MetaMethodType::Unknown || m.type == type))
                return m;
        if (type == MetaMethodType::Unknown) {
            for (const MetaMethod& m : cls->methods)
                if (m.name == name) return m;
        }
    }
    return std::nullopt;
}

bool InvokeEngine::decodePropertyBuffer(const std::string& type, const uint8_t* raw,
                                        PropertyValue* out) {
    // raw = 32-byte value buffer filled by the target's ReadProperty metacall
    if (type == "QString" || type == "const QString &") {
        // QString object layout in the buffer
        if (L_.stringdata_kind == 0) {
            Address d = 0;
            memcpy(&d, raw, 8);
            if (!d || !r_.isReadable(d)) return false;
            int32_t size = 0;
            int64_t offset = 0;
            if (!r_.readI32(d + L_.str_hdr_size, &size)) return false;
            if (!r_.read(d + L_.str_hdr_offset, &offset, 8)) return false;
            if (size < 0 || size > 4096) return false;
            std::vector<char16_t> buf((size_t)(size > 0 ? size : 0));
            if (size > 0 && !r_.read(d + (Address)offset, buf.data(), (size_t)size * 2))
                return false;
            out->asString = utf16_to_utf8(buf.data(), (size_t)size);
        } else {
            Address ptr = 0;
            int64_t size = 0;
            memcpy(&ptr, raw + L_.str_ptr, 8);
            memcpy(&size, raw + L_.str_size, 8);
            if (size < 0 || size > 4096) return false;
            if (size == 0) { out->asString.clear(); out->valid = true; return true; }
            if (!r_.isReadable(ptr)) return false;
            std::vector<char16_t> buf((size_t)size);
            if (!r_.read(ptr, buf.data(), (size_t)size * 2)) return false;
            out->asString = utf16_to_utf8(buf.data(), (size_t)size);
        }
        out->valid = true;
        return true;
    }
    if (type == "int" || type == "bool" || type == "uint") {
        int32_t v = 0;
        memcpy(&v, raw, 4);
        out->asInt = v;
        out->valid = true;
        return true;
    }
    if (type == "double" || type == "float" || type == "qreal") {
        double v = 0;
        memcpy(&v, raw, 8);
        out->asDouble = v;
        out->valid = true;
        return true;
    }
    if (type == "QRect" || type == "QRectF") {
        out->rect.resize(4);
        memcpy(out->rect.data(), raw, 16);
        out->valid = true;
        return true;
    }
    // unknown: raw ints
    int32_t v = 0;
    memcpy(&v, raw, 4);
    out->asInt = v;
    out->valid = true;
    return true;
}

InvokeResult InvokeEngine::invokeMethod(const DiscoveredObject& obj,
                                         const std::string& methodName,
                                         const std::vector<InvokeArg>& args) {
    InvokeResult res;
    if (!ex_) { res.detail = "no remote executor (read-only analysis)"; return res; }
    auto m = findOwnerMethod(obj, methodName, MetaMethodType::Unknown);
    if (!m) { res.detail = "method not found: " + methodName; return res; }
    Address fn = m->staticMetacall;
    if (!fn || !r_.isExecutable(fn)) {
        fn = r_.readPtr(m->metaObject + L_.mo_static_metacall);
        if (!fn || !r_.isExecutable(fn)) { res.detail = "no static_metacall"; return res; }
    }

    // argv: [0]=ret storage, [1..n]=args
    size_t argvLen = (1 + args.size()) * 8;
    Address argv = ex_->allocScratch(argvLen + 64);
    if (!argv) { res.detail = "scratch alloc failed"; return res; }
    Address retBuf = argv + argvLen;
    uint64_t z[10] = {0};
    ex_->writeScratch(argv, z, sizeof z);

    std::vector<Address> argBuffers;
    for (size_t i = 0; i < args.size(); ++i) {
        Address slot = argv + (1 + i) * 8;
        switch (args[i].kind) {
        case InvokeArg::Int: {
            Address b = ex_->allocScratch(8);
            uint64_t v = (uint64_t)args[i].i;
            ex_->writeScratch(b, &v, 8);
            ex_->writeScratch(slot, &b, 8);
            argBuffers.push_back(b);
            break;
        }
        case InvokeArg::Double: {
            Address b = ex_->allocScratch(8);
            ex_->writeScratch(b, &args[i].d, 8);
            ex_->writeScratch(slot, &b, 8);
            argBuffers.push_back(b);
            break;
        }
        case InvokeArg::Str: {
            // QString per family
            Address strObj = ex_->allocScratch((size_t)L_.str_obj_size + 64);
            if (L_.stringdata_kind == 0) {
                Address d = ex_->allocScratch(24 + args[i].s.size() * 2 + 8);
                uint8_t hdr[24] = {0};
                int32_t sz = (int32_t)args[i].s.size();
                int64_t off = 24;
                memcpy(hdr + 4, &sz, 4);
                memcpy(hdr + 16, &off, 8);
                ex_->writeScratch(d, hdr, 24);
                // UTF-16 chars
                std::vector<char16_t> w(args[i].s.begin(), args[i].s.end());
                ex_->writeScratch(d + 24, w.data(), w.size() * 2);
                ex_->writeScratch(strObj, &d, 8);
                argBuffers.push_back(d);
            } else {
                Address chars = ex_->allocScratch(args[i].s.size() * 2 + 8);
                std::vector<char16_t> w(args[i].s.begin(), args[i].s.end());
                ex_->writeScratch(chars, w.data(), w.size() * 2);
                uint64_t d0 = 0;
                int64_t sz = (int64_t)w.size();
                ex_->writeScratch(strObj, &d0, 8);
                ex_->writeScratch(strObj + L_.str_ptr, &chars, 8);
                ex_->writeScratch(strObj + L_.str_size, &sz, 8);
                argBuffers.push_back(chars);
            }
            ex_->writeScratch(slot, &strObj, 8);
            argBuffers.push_back(strObj);
            break;
        }
        }
    }
    ex_->writeScratch(argv, &retBuf, 8);   // argv[0] = ret storage

    RemoteCall c;
    c.fn = fn;
    c.args[0] = obj.object;
    c.args[1] = 0;                 // QMetaObject::InvokeMetaMethod
    c.args[2] = (uint64_t)(int64_t)m->localIndex;
    c.args[3] = argv;
    c.nargs = 4;
    uint64_t ret = 0;
    if (!ex_->call(c, &ret)) {
        res.detail = "remote call failed";
        for (Address a : argBuffers) ex_->freeScratch(a);
        ex_->freeScratch(argv);
        return res;
    }
    res.ok = true;
    res.calledFn = fn;
    res.strategy = "qt_static_metacall(InvokeMetaMethod)";
    res.detail = methodName + " -> " + m->ownerClass + "::" + m->name;
    for (Address a : argBuffers) ex_->freeScratch(a);
    ex_->freeScratch(argv);
    return res;
}

std::optional<PropertyValue> InvokeEngine::readProperty(const DiscoveredObject& obj,
                                                         const std::string& propName) {
    if (!ex_) return std::nullopt;
    for (Address mo : mr_.metaChain(obj.metaObject)) {
        auto cls = mr_.parseMetaClass(mo);
        if (!cls) continue;
        for (const MetaProperty& p : cls->properties) {
            if (p.name != propName) continue;
            Address fn = r_.readPtr(mo + L_.mo_static_metacall);
            if (!fn || !r_.isExecutable(fn)) return std::nullopt;
            Address argv = ex_->allocScratch(8 + 64);
            if (!argv) return std::nullopt;
            Address valueBuf = argv + 8;
            uint64_t z[8] = {0};
            ex_->writeScratch(argv, z, sizeof z);
            ex_->writeScratch(argv, &valueBuf, 8);
            RemoteCall c;
            c.fn = fn;
            c.args[0] = obj.object;
            c.args[1] = 1;              // QMetaObject::ReadProperty
            c.args[2] = (uint64_t)(int64_t)p.localIndex;
            c.args[3] = argv;
            uint64_t ret = 0;
            bool ok = ex_->call(c, &ret);
            PropertyValue pv;
            if (ok) {
                uint8_t raw[64] = {0};
                ex_->readScratch(valueBuf, raw, 64);
                decodePropertyBuffer(p.type, raw, &pv);
            }
            ex_->freeScratch(argv);
            if (pv.valid) return pv;
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::vector<std::string> InvokeEngine::comboItems(const DiscoveredObject& combo) {
    std::vector<std::string> out;
    auto count = readProperty(combo, "count");
    if (!count) return out;
    int n = (int)count->asInt;
    if (n < 0 || n > 256) n = 0;
    for (int i = 0; i < n; ++i) {
        // invoke itemText(int) and decode the returned QString from argv[0]
        auto m = findOwnerMethod(combo, "itemText", MetaMethodType::Unknown);
        if (!m) break;
        Address fn = m->staticMetacall;
        if (!fn || !r_.isExecutable(fn)) {
            fn = r_.readPtr(m->metaObject + L_.mo_static_metacall);
            if (!fn || !r_.isExecutable(fn)) break;
        }
        Address argv = ex_->allocScratch(8 + 64);
        if (!argv) break;
        Address retBuf = argv + 8;
        uint64_t z[8] = {0};
        ex_->writeScratch(argv, z, sizeof z);
        Address argInt = ex_->allocScratch(8);
        int64_t iv = i;
        ex_->writeScratch(argInt, &iv, 8);
        ex_->writeScratch(argv + 8, &argInt, 8);      // argv[1] = &i
        ex_->writeScratch(argv, &retBuf, 8);         // argv[0] = ret storage
        RemoteCall c;
        c.fn = fn;
        c.args[0] = combo.object;
        c.args[1] = 0;                                // InvokeMetaMethod
        c.args[2] = (uint64_t)(int64_t)m->localIndex;
        c.args[3] = argv;
        uint64_t ret = 0;
        std::string item;
        if (ex_->call(c, &ret)) {
            uint8_t raw[64] = {0};
            ex_->readScratch(retBuf, raw, 64);
            PropertyValue pv;
            if (decodePropertyBuffer("QString", raw, &pv)) item = pv.asString;
        }
        ex_->freeScratch(argInt);
        ex_->freeScratch(argv);
        if (item.empty() && i > 0) break;             // stop on empty returns
        out.push_back(item);
    }
    return out;
}

InvokeResult InvokeEngine::emitSignal(const DiscoveredObject& sender,
                                      const std::string& signalName,
                                      const std::vector<InvokeArg>& args) {
    InvokeResult res;
    if (!ex_) { res.detail = "no remote executor"; return res; }
    auto conns = cs_.outgoing(sender);
    int fired = 0;
    for (const ConnectionInfo& ci : conns) {
        if (!ci.signalName.empty() && ci.signalName != signalName) continue;
        if (ci.connectionType == "queued" || ci.connectionType == "blocking") continue;
        if (ci.isSlotObject) {
            // call the QSlotObjectBase impl with Call(=1)
            Address impl = r_.readPtr(ci.slotObject);
            if (!impl || !r_.isExecutable(impl)) continue;
            Address argv = ex_->allocScratch(64);
            Address retBuf = argv + 32;
            uint64_t z[8] = {0};
            ex_->writeScratch(argv, z, sizeof z);
            ex_->writeScratch(argv, &retBuf, 8);
            RemoteCall c;
            c.fn = impl;
            if (L_.stringdata_kind == 0) {
                // Qt5: impl(int which, QSlotObjectBase* this_, QObject* r, void** a, bool* ret)
                c.args[0] = 1;               // Call
                c.args[1] = ci.slotObject;
                c.args[2] = ci.receiver;
                c.args[3] = argv;
                c.args[4] = retBuf;
                c.nargs = 5;
            } else {
                // Qt6: impl(QSlotObjectBase* this_, QObject* r, void** a, int which, bool* ret)
                c.args[0] = ci.slotObject;
                c.args[1] = ci.receiver;
                c.args[2] = argv;
                c.args[3] = 1;               // Call
                c.args[4] = retBuf;
                c.nargs = 5;
            }
            uint64_t ret = 0;
            if (ex_->call(c, &ret)) ++fired;
            ex_->freeScratch(argv);
        } else {
            // method connection: callFunction(receiver, InvokeMetaMethod, localIdx, argv)
            Address rmeta = receiverMetaObject(ci.receiver);
            if (!rmeta) continue;
            int local = ci.slotMethodIndex - mr_.methodOffset(rmeta);
            if (local < 0) continue;
            Address argv = ex_->allocScratch(64);
            Address retBuf = argv + 32;
            uint64_t z[8] = {0};
            ex_->writeScratch(argv, z, sizeof z);
            ex_->writeScratch(argv, &retBuf, 8);
            RemoteCall c;
            c.fn = ci.callFunction;
            c.args[0] = ci.receiver;
            c.args[1] = 0;
            c.args[2] = (uint64_t)(int64_t)local;
            c.args[3] = argv;
            uint64_t ret = 0;
            if (ex_->call(c, &ret)) ++fired;
            ex_->freeScratch(argv);
        }
    }
    res.ok = fired > 0 || conns.empty();
    res.calledFn = 0;
    res.strategy = "signal-emit (activate-equivalent)";
    res.detail = signalName + ": fired " + std::to_string(fired) + " connection(s)";
    return res;
}

InvokeResult InvokeEngine::click(const DiscoveredObject& button) {
    InvokeResult res = emitSignal(button, "clicked");
    InvokeResult slotCall = invokeMethod(button, "click");
    res.ok = res.ok || slotCall.ok;
    res.calledFn = slotCall.calledFn ? slotCall.calledFn : res.calledFn;
    res.strategy = "emit clicked" + std::string(slotCall.ok ? " + click() slot" : "");
    res.detail += " | " + slotCall.detail;
    return res;
}

InvokeResult InvokeEngine::guiClick(const DiscoveredObject& button) {
    InvokeResult res;
#ifdef _WIN32
    if (!button.winId) { res.detail = "no winId"; return res; }
    HWND hwnd = (HWND)button.winId;
    // center of the button rect (screen coords assumed set by the app)
    POINT pt = {(button.rect.x + button.rect.w / 2), (button.rect.y + button.rect.h / 2)};
    LPARAM lp = MAKELPARAM(pt.x, pt.y);
    PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
    PostMessageW(hwnd, WM_LBUTTONUP, 0, lp);
    res.ok = true;
    res.strategy = "gui-safe WM_LBUTTONDOWN/UP";
    res.detail = "hwnd=" + std::to_string((uint64_t)hwnd);
#else
    (void)button;
    res.detail = "guiClick available on Windows builds only";
#endif
    return res;
}

} // namespace umvpqt
