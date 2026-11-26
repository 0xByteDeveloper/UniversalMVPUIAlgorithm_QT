// UMVPQT GOD STATE — SDK Types
// ============================================================================
//  UniversalMVPUIAlgorithm_QT — Qt process'lerinin harici (external) bellek
//  analiziyle formlarini/widget'larini/event'lerini tespit eden GOD SDK.
//  Veri modeli (XPRO types.h tarzi).
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace umvpqt {

typedef uint64_t Addr;

enum class QtEra { Unknown, Qt4, Qt5, Qt6 };

struct QtInfo {
    bool        present = false;
    QtEra       era = QtEra::Unknown;
    std::string version;             // "6.8.2" (qVersion'dan veya imzadan)
    std::string coreModule;          // Qt Core modul yolu
    std::string widgetsModule;
    int         moRevision = 0;       // metaobject data revision (7,8,9..12)
    std::string detection;           // nasil bulundu
};

// ---- Bellek bolgesi ----
struct MemRegion {
    Addr  start = 0, end = 0;        // [start, end)
    Addr  fileOffset = 0;            // dosya eslemmesi offseti
    bool  read = false, write = false, exec = false;
    bool  priv = false;              // private (heap/stack gibi)
    std::string path;                // bos = anonim
};

// ---- Modul ----
struct Symbol {
    Addr        address = 0;
    std::string name;
    char        type = 0;            // T=tекст/data kod, D=data, W=weak...
};

struct Module {
    Addr        base = 0;
    Addr        end = 0;
    Addr        size = 0;
    std::string name;                // libQt6Core.so.6 / game.exe
    std::string path;
    bool        isQt = false;
    bool        isMainExe = false;
    std::vector<Symbol> symbols;     // sirali (address'e gore)
};

// ---- QString okuma sonucu ----
struct QtStr { std::string utf8; Addr dataPtr = 0; int64_t size = -1; bool valid = false; };

// ---- MetaObject bilgisi ----
struct MetaMethod {
    std::string name;        // "clicked"
    std::string signature;   // "clicked(bool)"
    uint32_t    flags = 0;   // MethodFlags
    int         parameterCount = 0;
    bool        isSignal = false, isSlot = false;
    Addr        codeAddress = 0;    // metacall switch cozumunden (varsa)
    std::string moduleOfCode;       // handler'in modulu
};

struct MetaProperty {
    std::string name;
    std::string type;
    uint32_t    flags = 0;
    bool        readable = false, writable = false;
};

struct MetaClassInfo {
    Addr              metaObject = 0;      // &staticMetaObject
    Addr              staticMetacall = 0;  // qt_static_metacall fn ptr
    std::string       className;           // "MainWindow"
    std::string       classNameResolved;   // RTTI'dan (Q_OBJECT'suz turetme)
    std::vector<std::string> superChain;  // QObject'a kadar
    std::vector<MetaMethod>  methods;
    std::vector<MetaProperty> properties;
    const class ModuleInfo* owner = nullptr; // doluysa Qt modulu
    int               signalCount = 0;
    bool              fromQtModule = false;
    std::map<int, Addr> methodCode;        // metacall cozumlemesi: idx -> kod adresi
};

// ---- Event / connection ----
struct ConnectionInfo {
    Addr        connection = 0;
    Addr        sender = 0, receiver = 0;
    std::string signalName;          // "clicked" + signal index
    int         signalIndex = -1;
    std::string signalSignature;
    std::string slotSignature;       // "on_btn_clicked()" — metaobject'dan
    int         slotMethodIndex = -1; // method_offset+relative
    Addr        slotCode = 0;        // PMF baglantilarinda gercek fonksiyon adresi
    Addr        callFunction = 0;    // receiver sinifinin qt_static_metacall
    bool        isSlotObject = false; // functor/lambda baglantisi
    std::string connectionType;      // auto/direct/queued/blocking
};

// ---- Form (top-level widget) ----
struct WidgetInfo {
    Addr        address = 0;
    Addr        vtable = 0;
    std::string className;           // "MainWindow" veya "QPushButton"
    std::string classNameResolved;   // vtable/metaobject'dan
    std::string objectName;
    std::string text;                // buton texti / label texti
    std::string windowTitle;
    int         x = 0, y = 0, w = 0, h = 0;  // crect
    int         globalX = 0, globalY = 0;
    bool        visible = false;
    bool        topLevel = false;
    Addr        parent = 0;
    std::vector<Addr> children;
    // event tespiti
    std::vector<ConnectionInfo> connections;   // bu widget'in SINYALLERINE baglananlar
    bool        hasClickHandler = false;
    std::string clickHandlerName;
    // handler code
    struct Handler {
        std::string kind;      // "slot" | "override" (paintEvent vb.)
        std::string name;      // "on_btn_clicked()" / "paintEvent"
        Addr        start = 0, end = 0;   // [start, end)
        std::string module;
    };
    std::vector<Handler> handlers;
    // combobox icerigi
    std::vector<std::string> comboItems;
    int         comboCurrentIndex = -1;
    std::string comboCurrentText;
    // line edit
    std::string editText;
    std::string toolTip;
};

struct FormInfo {
    Addr        address = 0;
    std::string className;
    std::string objectName;
    std::string windowTitle;
    bool        visible = false;
    int         x = 0, y = 0, w = 0, h = 0;
    int         widgetCount = 0;
    std::vector<WidgetInfo> widgets;  // cocuk agaci duz liste (depth ile)
};

struct AnalysisReport {
    uint64_t    pid = 0;
    std::string processName;
    QtInfo      qt;
    int         totalQObjects = 0;
    int         totalWidgets = 0;
    std::vector<FormInfo> forms;
    std::vector<MetaClassInfo> classes;   // tespit edilen tum meta class'lar
    std::vector<ConnectionInfo> allConnections;
    // monitor diff modu
    std::string diffSummary;
};

} // namespace umvpqt
