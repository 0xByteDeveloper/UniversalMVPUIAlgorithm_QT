// =============================================================================
// UMVP-QT // tests/mock/mock_qt.h — synthetic Qt process image.
// Builds an in-memory "target process" that is byte-layout identical to real
// Qt 5.15 / Qt 6.8 objects (replica ABI), including metaobjects, vtables
// whose metaObject() thunks point at real compiled functions, real compiled
// qt_static_metacall switches (jump-table fodder), connection graphs and
// widget data. The analyzer sees it through IProcessReader only.
// =============================================================================
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "umvpqt/process.h"
#include "umvpqt/qt_scan.h"

namespace umvpqt_mock {

using umvpqt::Address;

class MockImage {
public:
    static constexpr Address kBase = 0x10000000;
    static constexpr size_t kSize = 0x40000;     // 256 KB RWX image

    explicit MockImage(umvpqt::QtFamily fam);
    ~MockImage();

    umvpqt::QtFamily family() const { return fam_; }
    umvpqt::IProcessReader* reader();             // owned by image

    Address alloc(size_t n, size_t align = 8);
    void registerCode(void* fn);
    void poke8(Address at, uint64_t v);

    // --- builders ------------------------------------------------------------
    Address newString(const std::string& utf8);          // QString object
    struct MethodSpec { const char* name; int argc; int flags; };
    struct PropSpec { const char* name; const char* type; int flags; };
    Address newMetaObject(const char* className, Address super,
                          const std::vector<MethodSpec>& methods, int signalCount,
                          const std::vector<PropSpec>& props, void* staticMetacall);
    Address newVtable(Address metaObject, void* metacallFn,
                      void* overrideMousePress = nullptr);
    struct ObjectSpec {
        Address metaObject = 0;
        Address vtable = 0;
        Address parent = 0;
        const char* objectName = nullptr;
        int rect[4] = {0, 0, 0, 0};
        uint64_t winId = 0;
        bool inShow = false;
        int windowFlags = 0;
        const char* text = nullptr;
        std::vector<std::string> comboItems;
        int comboIndex = -1;
    };
    Address newQObject(const ObjectSpec& spec);
    void addChild(Address parentObj, Address childObj);
    void addMethodConnection(Address senderObj, int signalAbsIndex, Address receiverObj,
                             int slotAbsIndex, void* receiverStaticMetacall);
    void addFunctorConnection(Address senderObj, int signalAbsIndex, Address receiverObj,
                              void* slotObjImplFn, void* storageFn);

    // test-side / mock-metacall introspection (LOCAL data, not target memory)
    Address textStringOf(Address object) const;                 // QString obj in image
    Address comboItemString(Address object, int i) const;       // QString obj in image
    const std::vector<std::string>& comboItemsOf(Address object) const;
    int comboIndexOf(Address object) const;

    // world (builds everything, returns object addresses)
    struct World {
        Address form1, form2, button1, button2, combo1, label1, check1, myButton, timer1;
        Address meta_QObject, meta_QWidget, meta_QMainWindow, meta_QDialog,
            meta_QAbstractButton, meta_QPushButton, meta_QComboBox, meta_QLabel,
            meta_QCheckBox, meta_Form1, meta_MyButton, meta_QTimer;
    };
    World buildWorld();

private:
    struct Impl;
    Impl* impl_;
    umvpqt::QtFamily fam_;
    std::vector<uint8_t> buf_;
    size_t cursor_ = 0;
};

// mock metacall / handler side effects (test assertions read these)
extern int g_on_button1_clicked;
extern int g_on_check1_toggled;
extern int g_lambda_fired;
extern int g_button_click_slot;
extern int g_mouse_press_overridden;
extern int g_default_virtual_calls;
extern int g_on_combo1_idx_changed;
extern int g_combo_itemtext_calls;

} // namespace umvpqt_mock
