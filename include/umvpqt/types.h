// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/types.h
// Data model of the analysis report (forms, widgets, events, handlers).
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#include "qt_layout.h"

namespace umvpqt {

enum class Arch { Unknown, X64, X86 };

struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;
    Arch arch = Arch::Unknown;
};

// --- meta object model --------------------------------------------------------
enum class MetaMethodType { Signal, Slot, Method, Constructor, Unknown };

inline const char* to_string(MetaMethodType t) {
    switch (t) {
    case MetaMethodType::Signal: return "signal";
    case MetaMethodType::Slot:   return "slot";
    case MetaMethodType::Method: return "method";
    case MetaMethodType::Constructor: return "constructor";
    default: return "?";
    }
}

struct MetaMethod {
    std::string name;              // e.g. "clicked"
    std::string signature;          // e.g. "clicked(bool)"
    MetaMethodType type = MetaMethodType::Unknown;
    std::string access;             // private/protected/public
    std::vector<std::string> paramTypes;
    std::vector<std::string> paramNames;
    int localIndex = -1;            // index within owner class methodData
    int absoluteIndex = -1;         // method_offset + local
    std::string ownerClass;         // resolved owning class in the chain
    Address metaObject = 0;
    Address staticMetacall = 0;     // owner metaobject's static_metacall fn
    int flags = 0;
};

struct MetaProperty {
    std::string name;
    std::string type;
    int localIndex = -1;
    std::string ownerClass;
    Address metaObject = 0;
    int flags = 0;
    bool readable = false, writable = false;
};

struct MetaClass {
    std::string className;
    Address metaObject = 0;
    int revision = -1;
    int methodCount = 0, signalCount = 0, propertyCount = 0;
    std::vector<MetaMethod> methods;     // local methods only
    std::vector<MetaProperty> properties; // local properties only
    Address superMetaObject = 0;
    std::string superClassName;
};

// --- connections --------------------------------------------------------------
struct ConnectionInfo {
    Address connection = 0;
    Address sender = 0;
    Address receiver = 0;           // 0 => disconnected/lambda w/o receiver ctx
    int signalIndex = -1;           // absolute signal index
    std::string signalName;         // resolved ("" if unresolved)
    std::string signalOwnerClass;
    int slotMethodIndex = -1;        // absolute (method_offset+relative)
    std::string slotName;
    std::string slotOwnerClass;
    bool isSlotObject = false;      // functor/lambda connection
    Address slotObject = 0;
    Address callFunction = 0;       // receiver static_metacall (non-functor)
    Address slotFunction = 0;       // resolved handler entry (slot body or impl)
    std::string connectionType;     // auto/direct/queued/blocking
    uint32_t id = 0;
};

// --- widgets ------------------------------------------------------------------
struct Rect { int x = 0, y = 0, w = 0, h = 0; };

struct DisasmBlock {
    Address base = 0, end = 0;
    std::vector<std::string> lines;  // one instruction per line
    size_t instructionCount = 0;
};

struct HandlerInfo {
    std::string ownerClass;
    std::string methodName;         // slot/override name
    Address entry = 0;               // resolved function address
    Address base = 0, end = 0;      // [base,end) code range
    DisasmBlock disasm;
    Address via = 0;                 // static_metacall / vtable slot used
    std::string viaKind;             // "qt_static_metacall" / "vtable-slot" / "slot-object"
    int confidence = 0;              // 0..100
};

struct WidgetInfo {
    Address object = 0;
    Address vtable = 0;
    std::string className;           // most-derived class name
    std::vector<std::string> classChain; // derived -> base
    std::string objectName;
    // widget visuals (memory mode)
    Rect rect;                        // crect (exact for QWidget)
    bool hasRect = false;
    uint64_t winId = 0;
    int windowFlags = 0;
    bool visible = false;             // in_show heuristic + flags
    bool isWidget = false;
    bool isWindow = false;
    // text heuristics (QAbstractButton/QLabel/QLineEdit best-effort)
    std::string text;
    int textConfidence = 0;
    // combobox specifics
    std::vector<std::string> comboItems;   // via invoke path / heuristic
    int comboCurrentIndex = -1;
    std::string comboCurrentText;
    int comboConfidence = 0;
    // event / handler knowledge
    std::vector<ConnectionInfo> outgoingConnections; // signals OF this widget
    std::vector<ConnectionInfo> incomingConnections; // slots OF this widget
    bool hasEventHandlers = false;     // ANY handler found (connection or override)
    std::vector<HandlerInfo> handlers;  // resolved handlers w/ code ranges
    std::vector<std::string> overriddenVirtuals; // vtable overrides vs base class
    std::vector<MetaProperty> metaProperties;
    Address metaObject = 0;
    Address staticMetacall = 0;
    int depth = 0;                    // tree depth
    Address parentObject = 0;
};

struct FormInfo {
    std::string className;             // QMainWindow / QDialog / custom
    std::string objectName;
    Address object = 0;
    Rect rect;
    uint64_t winId = 0;
    bool isActive = false;             // foreground heuristic
    bool visible = false;
    std::vector<WidgetInfo> widgets;   // recursive children (widgets only)
    int widgetCount = 0;
    std::vector<Address> allChildren; // every QObject in subtree
};

struct InvokeResult {
    bool ok = false;
    std::string detail;
    Address calledFn = 0;
    std::string strategy;              // qt_static_metacall / signal-emit / vtable
};

struct AnalysisReport {
    ProcessInfo process;
    QtVersion qt;
    std::vector<FormInfo> forms;
    int activeForm = -1;               // index into forms
    std::vector<WidgetInfo> allObjects; // flat list of every QObject found
    int objectCount = 0;
    int connectionCount = 0;
    int handlerCount = 0;
    // stats for verification
    int verifiedQObjects = 0;
};

} // namespace umvpqt
