// =============================================================================
// UMVP-QT // tests/test_analyzer.cpp — end-to-end on the mock image:
// version detection, heap sweep finds all 9 objects, form count = 2,
// active form = Form1, widget tree, text/rect heuristics, combobox state,
// "olay VAR/YOK" determination for every widget, vtable override detection.
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "mock/mock_qt.h"
#include "umvpqt/analyzer.h"
#include "umvpqt/report.h"

using namespace umvpqt;
using umvpqt_mock::MockImage;

static int failures = 0, checks = 0;

void expect_b(const char* what, bool got, bool want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("  FAIL %s: got=%d want=%d\n", what, got ? 1 : 0, want ? 1 : 0);
    }
}
void expect_i(const char* what, long long got, long long want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("  FAIL %s: got=%lld want=%lld\n", what, got, want);
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
    img.buildWorld();

    Analyzer analyzer(*img.reader());
    AnalyzerOptions opt;
    opt.live = true;
    opt.code = true;
    opt.invoke = false;        // pure memory mode (test_invoke covers god mode)
    AnalysisReport rep = analyzer.analyze(opt);

    // ---- version ----
    expect_i("family", (long long)rep.qt.family, (long long)fam);
    expect_i("revision", (long long)rep.qt.revision, fam == QtFamily::Qt5 ? 8 : 12);

    // ---- object count: form1,form2,button1,button2,combo1,label1,check1,myButton,timer1
    expect_i("object count", rep.objectCount, 9);
    expect_i("verified count", rep.verifiedQObjects, 9);

    // ---- forms ----
    expect_i("form count", (long long)rep.forms.size(), 2);
    if (rep.forms.size() == 2) {
        expect_s("form0 className", rep.forms[0].className, "Form1");
        expect_s("form0 objectName", rep.forms[0].objectName, "Form1");
        expect_b("form0 active", rep.forms[0].isActive, true);
        expect_b("form1 not active", rep.forms[1].isActive, false);
        expect_s("form1 className", rep.forms[1].className, "QDialog");
        expect_i("active form index", rep.activeForm, 0);
        expect_i("form0 widget count", rep.forms[0].widgetCount, 6);
        if (rep.forms[0].widgets.size() == 6) {
            const WidgetInfo& b1 = rep.forms[0].widgets[0];
            expect_s("widget0 class", b1.className, "QPushButton");
            expect_s("widget0 name", b1.objectName, "button1");
            expect_s("widget0 text", b1.text, "Kaydet");
            expect_i("widget0 text confidence", b1.textConfidence, 70);
            expect_i("widget0 x", b1.rect.x, 20);
            expect_i("widget0 w", b1.rect.w, 120);
            expect_i("widget0 h", b1.rect.h, 28);
            expect_i("widget0 winId", (long long)b1.winId, 0x21C03);
            expect_b("widget0 has event handlers", b1.hasEventHandlers, true);
            expect_i("widget0 handler count", (long long)b1.handlers.size(), 1);
            if (!b1.handlers.empty()) {
                expect_i("handler range valid",
                         b1.handlers[0].end > b1.handlers[0].base ? 1 : 0, 1);
                expect_i("handler disasm non-empty",
                         (long long)b1.handlers[0].disasm.instructionCount > 0 ? 1 : 0, 1);
                expect_s("handler via", b1.handlers[0].viaKind, "qt_static_metacall");
            }
            expect_i("widget0 connection count",
                     (long long)b1.outgoingConnections.size(), 1);

            const WidgetInfo& b2 = rep.forms[0].widgets[1];
            expect_s("widget1 name", b2.objectName, "button2");
            expect_s("widget1 text", b2.text, "Iptal");
            expect_b("widget1 functor handler", !b2.handlers.empty(), true);
            if (!b2.handlers.empty())
                expect_s("widget1 via", b2.handlers[0].viaKind, "slot-object");

            const WidgetInfo& combo = rep.forms[0].widgets[2];
            expect_s("widget2 class", combo.className, "QComboBox");
            expect_b("widget2 combo items found", !combo.comboItems.empty(), true);
            if (combo.comboItems.size() == 3) {
                expect_s("item0", combo.comboItems[0], "A");
                expect_s("item1", combo.comboItems[1], "B");
                expect_s("item2", combo.comboItems[2], "C");
            }
            expect_i("combo current index", combo.comboCurrentIndex, 1);
            expect_s("combo current text", combo.comboCurrentText, "B");
            expect_b("combo olay YOK", combo.outgoingConnections.empty(), true);
            expect_b("combo hasEventHandlers false", combo.hasEventHandlers, false);

            const WidgetInfo& lbl = rep.forms[0].widgets[3];
            expect_s("widget3 class", lbl.className, "QLabel");
            expect_s("widget3 text", lbl.text, "Aciklama:");
            expect_b("label olay YOK", lbl.outgoingConnections.empty(), true);

            const WidgetInfo& chk = rep.forms[0].widgets[4];
            expect_s("widget4 class", chk.className, "QCheckBox");
            expect_s("widget4 text", chk.text, "Aktif");
            expect_b("widget4 toggled connected", !chk.outgoingConnections.empty(), true);

            const WidgetInfo& myb = rep.forms[0].widgets[5];
            expect_s("widget5 class", myb.className, "MyButton");
            expect_b("widget5 mousePressEvent override detected",
                     !myb.overriddenVirtuals.empty(), true);
            if (!myb.overriddenVirtuals.empty())
                expect_s("override name", myb.overriddenVirtuals[0], "mousePressEvent");
        }
    }

    // ---- allObjects includes non-widget QTimer ----
    bool foundTimer = false;
    for (const WidgetInfo& o : rep.allObjects)
        if (o.className == "QTimer" && o.objectName == "timer1") foundTimer = true;
    expect_b("non-widget QObject (QTimer) enumerated", foundTimer, true);

    // ---- report renders ----
    std::string txt = report_text(rep);
    expect_b("text report mentions button1", txt.find("button1") != std::string::npos, true);
    expect_b("text report mentions Kaydet", txt.find("Kaydet") != std::string::npos, true);
    expect_b("text report mentions olay YOK", txt.find("olay: YOK") != std::string::npos, true);
    expect_b("text report mentions handler block",
             txt.find("handler kod blogu") != std::string::npos, true);
    std::string js = report_json(rep);
    while (!js.empty() && (js.back() == '\n' || js.back() == ' ' || js.back() == '\r')) js.pop_back();
    expect_b("json parses structurally (balanced)",
             js.front() == '{' && js.back() == '}', true);
    expect_b("json has forms", js.find("\"forms\"") != std::string::npos, true);
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("[%s] test_analyzer: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
