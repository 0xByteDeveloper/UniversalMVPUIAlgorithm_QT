// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/qt_invoke.h
// GOD MODE invoke engine:
//   * invokeMethod     — qt_static_metacall(obj, InvokeMetaMethod, local, argv)
//   * readProperty     — qt_static_metacall(obj, ReadProperty, local, argv)
//   * emitSignal       — walks the live connection list (like activate) and
//                        fires every direct connection
//   * click            — "button1'e basilsin" = emit clicked + call click()
// Execution backends: MockRemoteExecutor (tests, in-process), Windows
// CreateRemoteThread shellcode (production). Signal emission can also use
// the exported QMetaObject::activate via PE export resolution.
// =============================================================================
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "process.h"
#include "qt_layout.h"
#include "qt_meta.h"
#include "qt_scan.h"
#include "qt_signals.h"
#include "types.h"

namespace umvpqt {

// ---- remote execution backend -------------------------------------------------
struct RemoteCall {
    Address fn = 0;
    uint64_t args[5] = {0, 0, 0, 0, 0};
    int nargs = 4;
    bool hasRet = false;
};

class IRemoteExecutor {
public:
    virtual ~IRemoteExecutor() = default;
    virtual bool call(const RemoteCall& c, uint64_t* ret) = 0;
    // scratch buffers inside the TARGET address space
    virtual Address allocScratch(size_t len) = 0;
    virtual bool readScratch(Address a, void* buf, size_t len) = 0;
    virtual bool writeScratch(Address a, const void* buf, size_t len) = 0;
    virtual void freeScratch(Address a) = 0;
    virtual std::string describe() const = 0;
};

// ---- invoke engine -------------------------------------------------------------
struct InvokeArg {
    enum Kind { Int, Double, Str } kind = Int;
    int64_t i = 0;
    double d = 0.0;
    std::string s;
    static InvokeArg of(int64_t v) { InvokeArg a; a.kind = Int; a.i = v; return a; }
    static InvokeArg of(double v) { InvokeArg a; a.kind = Double; a.d = v; return a; }
    static InvokeArg of(const std::string& v) { InvokeArg a; a.kind = Str; a.s = v; return a; }
};

struct PropertyValue {
    bool valid = false;
    int64_t asInt = 0;
    double asDouble = 0.0;
    std::string asString;
    std::vector<int32_t> rect;    // QRect as 4 ints when applicable
};

class InvokeEngine {
public:
    InvokeEngine(IProcessReader& r, const QtLayout& L, IRemoteExecutor* ex)
        : r_(r), L_(L), mr_(r, L), ex_(ex), cs_(r, L) {}

    bool available() const { return ex_ != nullptr; }

    // invoke a slot / Q_INVOKABLE by name
    InvokeResult invokeMethod(const DiscoveredObject& obj, const std::string& methodName,
                              const std::vector<InvokeArg>& args = {});

    // read a meta-property by name (text/currentIndex/currentText/count/...)
    std::optional<PropertyValue> readProperty(const DiscoveredObject& obj,
                                             const std::string& propName);

    // enumerate combobox items through itemText(0..count-1)
    std::vector<std::string> comboItems(const DiscoveredObject& combo);

    // emit a signal (direct connections fire exactly like QMetaObject::activate)
    InvokeResult emitSignal(const DiscoveredObject& sender, const std::string& signalName,
                            const std::vector<InvokeArg>& args = {});

    // "button1'e bas": fire clicked connections + call the click() slot
    InvokeResult click(const DiscoveredObject& button);

    // GUI-safe Win32 click via WM_LBUTTONDOWN/UP on the button's hwnd
    // (Windows builds; winId taken from QWidgetData).
    InvokeResult guiClick(const DiscoveredObject& button);

private:
    Address receiverMetaObject(Address receiverObject);
    std::optional<MetaMethod> findOwnerMethod(const DiscoveredObject& obj,
                                              const std::string& name,
                                              MetaMethodType type);
    bool decodePropertyBuffer(const std::string& typeName, const uint8_t* raw32,
                               PropertyValue* out);

    IProcessReader& r_;
    const QtLayout& L_;
    MetaObjectReader mr_;
    IRemoteExecutor* ex_;
    ConnectionScanner cs_;
};

} // namespace umvpqt
