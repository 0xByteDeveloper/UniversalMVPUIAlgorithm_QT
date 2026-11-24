// =============================================================================
// UMVP-QT // tests/test_metaobj.cpp — QMetaObject decode on both families:
// class chain, signals/slots/properties, absolute index resolution,
// stringdata decoding (Qt5 24-byte entries vs Qt6 uint pairs).
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "mock/mock_qt.h"
#include "umvpqt/qt_meta.h"

using namespace umvpqt;
using umvpqt_mock::MockImage;

static int failures = 0, checks = 0;

template <typename T>
void expect(const char* what, T got, T want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("  FAIL %s: got=[%s] want=[%s]\n", what,
                    std::to_string((long long)got).c_str(),
                    std::to_string((long long)want).c_str());
    }
}
void expect_s(const char* what, const std::string& got, const std::string& want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("  FAIL %s: got=[%s] want=[%s]\n", what, got.c_str(), want.c_str());
    }
}

static void run_family(QtFamily fam) {
    std::printf("-- family %s --\n", fam == QtFamily::Qt5 ? "Qt5" : "Qt6");
    MockImage img(fam);
    auto w = img.buildWorld();
    const QtLayout& L = *layout_for(fam);
    MetaObjectReader mr(*img.reader(), L);

    // class chain of button1
    {
        std::vector<std::string> chain = mr.classChain(w.meta_QPushButton);
        expect_s("chain.size", std::to_string(chain.size()), "4");
        if (chain.size() >= 5) {
            expect_s("chain[0]", chain[0], "QPushButton");
        expect_s("chain[1]", chain[1], "QAbstractButton");
        expect_s("chain[2]", chain[2], "QWidget");
        expect_s("chain[3]", chain[3], "QObject");
        }
    }
    // className via decodeString
    expect_s("decodeString(QComboBox)", mr.decodeString(w.meta_QComboBox, 0), "QComboBox");

    // method counts
    expect("methodCount(QComboBox)", (long long)mr.methodCountOf(w.meta_QComboBox), 9LL);
    expect("signalCount(QComboBox)", (long long)mr.signalCountOf(w.meta_QComboBox), 4LL);
    expect("methodCount(Form1)", (long long)mr.methodCountOf(w.meta_Form1), 5LL);

    // signals of QAbstractButton (local 0..4)
    {
        auto cls = mr.parseMetaClass(w.meta_QAbstractButton);
        expect("QAbstractButton methods", (long long)(cls ? cls->methods.size() : 0), 8LL);
        if (cls) {
            expect_s("sig0 clicked", cls->methods[0].name, "clicked");
            expect_s("sig0 type", std::string(to_string(cls->methods[0].type)), "signal");
            expect_s("sig1 clicked(no-arg)", cls->methods[1].name, "clicked");
            expect_s("slot5 click", cls->methods[5].name, "click");
            expect_s("slot5 type", std::string(to_string(cls->methods[5].type)), "slot");
            expect("param count of toggled", (long long)cls->methods[4].paramTypes.size(), 1LL);
        }
    }
    // absolute signal resolution: clicked = 4 (QObject 2 + QWidget 2 + local 0)
    {
        Address owner = 0;
        int local = -1;
        auto m = mr.resolveSignalByAbsIndex(w.meta_QPushButton, 4, &owner, &local);
        expect_s("clicked resolved", m ? m->name : "<none>", "clicked");
        expect("clicked owner is QAbstractButton", (long long)(owner == w.meta_QAbstractButton), 1LL);
        expect("clicked local", (long long)local, 0LL);
    }
    // absolute signal resolution: toggled = 8
    {
        auto m = mr.resolveSignalByAbsIndex(w.meta_QPushButton, 8, nullptr, nullptr);
        expect_s("toggled resolved", m ? m->name : "<none>", "toggled");
    }
    // absolute method resolution: Form1::on_button1_clicked = abs 11
    {
        Address owner = 0;
        int local = -1;
        bool ok = mr.resolveMethodByAbsIndex(w.meta_Form1, 11, &owner, &local);
        expect("abs11 ok", (long long)ok, 1LL);
        expect("abs11 owner", (long long)(owner == w.meta_Form1), 1LL);
        expect("abs11 local", (long long)local, 1LL);
    }
    // methodOffset(Form1) = 3 + 5 + 2 = 10
    expect("methodOffset(Form1)", (long long)mr.methodOffset(w.meta_Form1), 10LL);
    // findMethod by name in chain
    {
        auto m = mr.findMethod(w.meta_QPushButton, "click", MetaMethodType::Slot);
        expect_s("findMethod click", m ? m->name : "<none>", "click");
        expect("click localIndex", (long long)(m ? m->localIndex : -1), 5LL);
        expect("click absoluteIndex", (long long)(m ? m->absoluteIndex : -1), 13LL);   // 3+5+2+5
    }
    // properties of QComboBox
    {
        auto props = mr.allProperties(w.meta_QComboBox);
        // QObject:0 props; QWidget: 3 (windowTitle/enabled/visible); QComboBox: 4
        expect("combo props (chain)", (long long)props.size(), 7LL);
        if (props.size() == 7) {
            expect_s("prop3", props[3].name, "currentIndex");
            expect_s("prop4", props[4].name, "currentText");
            expect_s("prop4 type", props[4].type, "QString");
        }
    }
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("[%s] test_metaobj: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
