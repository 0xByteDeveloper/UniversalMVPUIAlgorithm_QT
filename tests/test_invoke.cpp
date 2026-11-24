// =============================================================================
// UMVP-QT // tests/test_invoke.cpp — GOD MODE invoke engine:
//   * invokeMethod("click")        -> real compiled slot body runs
//   * emitSignal("clicked")       -> connection graph fires (activate-style)
//   * readProperty("text")         -> "Kaydet" read back through metacall
//   * comboItems()                 -> A|B|C through itemText(i) invocations
//   * click()                      -> "button1'e basilsin" end-to-end
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "mock/mock_executor.h"
#include "mock/mock_qt.h"
#include "umvpqt/analyzer.h"
#include "umvpqt/qt_invoke.h"
#include "umvpqt/qt_meta.h"
#include "umvpqt/qt_scan.h"

using namespace umvpqt;
using umvpqt_mock::MockImage;
using umvpqt_mock::MockRemoteExecutor;

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
    umvpqt_mock::g_on_button1_clicked = 0;
    umvpqt_mock::g_on_check1_toggled = 0;
    umvpqt_mock::g_lambda_fired = 0;
    umvpqt_mock::g_button_click_slot = 0;
    umvpqt_mock::g_mouse_press_overridden = 0;
    umvpqt_mock::g_on_combo1_idx_changed = 0;
    umvpqt_mock::g_combo_itemtext_calls = 0;
    MockImage img(fam);
    auto w = img.buildWorld();
    const QtLayout& L = *layout_for(fam);
    IProcessReader* rd = img.reader();

    ObjectScanner scanner(*rd, L);
    auto b1 = scanner.parseObjectNode(w.button1);
    auto b2 = scanner.parseObjectNode(w.button2);
    auto c1 = scanner.parseObjectNode(w.combo1);
    expect_b("button1 parses", b1.has_value(), true);
    if (!b1 || !b2 || !c1) return;

    MockRemoteExecutor ex;
    InvokeEngine inv(*rd, L, &ex);

    // ---- baseline counters are 0 ----
    expect_i("g_on_button1_clicked starts 0", umvpqt_mock::g_on_button1_clicked, 0);
    expect_i("g_button_click_slot starts 0", umvpqt_mock::g_button_click_slot, 0);
    expect_i("g_lambda_fired starts 0", umvpqt_mock::g_lambda_fired, 0);

    // ---- invokeMethod: QAbstractButton::click() ----
    InvokeResult r1 = inv.invokeMethod(*b1, "click");
    expect_b("click() invoked", r1.ok, true);
    expect_b("click() hit the compiled slot body",
             umvpqt_mock::g_button_click_slot == 1, true);
    expect_b("click() called qt_static_metacall",
             r1.calledFn == rd->readPtr(w.meta_QAbstractButton + L.mo_static_metacall), true);

    // ---- emitSignal: button1 clicked -> Form1::on_button1_clicked ----
    InvokeResult r2 = inv.emitSignal(*b1, "clicked");
    expect_b("emitSignal(clicked) ok", r2.ok, true);
    expect_b("handler fired via connection graph",
             umvpqt_mock::g_on_button1_clicked == 1, true);

    // ---- emitSignal: button2 clicked -> functor ----
    InvokeResult r3 = inv.emitSignal(*b2, "clicked");
    expect_b("lambda fired via slot-object impl", umvpqt_mock::g_lambda_fired >= 1, true);

    // ---- click(): the full "button1'e bas" god mode ----
    long long before = umvpqt_mock::g_on_button1_clicked + umvpqt_mock::g_button_click_slot;
    InvokeResult r4 = inv.click(*b1);
    expect_b("click() god-mode ok", r4.ok, true);
    long long after = umvpqt_mock::g_on_button1_clicked + umvpqt_mock::g_button_click_slot;
    expect_b("click() fired both strategies", after - before == 2, true);

    // ---- readProperty: text ----
    auto text = inv.readProperty(*b1, "text");
    expect_b("text property read", text.has_value(), true);
    if (text) expect_s("text property value", text->asString, "Kaydet");

    // ---- readProperty: combo currentIndex/currentText/count ----
    auto idx = inv.readProperty(*c1, "currentIndex");
    expect_b("currentIndex read", idx.has_value(), true);
    if (idx) expect_i("currentIndex value", idx->asInt, 1);
    auto ctxt = inv.readProperty(*c1, "currentText");
    expect_b("currentText read", ctxt.has_value(), true);
    if (ctxt) expect_s("currentText value", ctxt->asString, "B");
    auto cnt = inv.readProperty(*c1, "count");
    expect_b("count read", cnt.has_value(), true);
    if (cnt) expect_i("count value", cnt->asInt, 3);

    // ---- comboItems via itemText(i) ----
    auto items = inv.comboItems(*c1);
    expect_i("combo item count", (long long)items.size(), 3);
    if (items.size() == 3) {
        expect_s("item0", items[0], "A");
        expect_s("item1", items[1], "B");
        expect_s("item2", items[2], "C");
    }

    // ---- invoke a Form1 slot directly through the receiver metacall ----
    auto form1 = scanner.parseObjectNode(w.form1);
    expect_b("form1 parses", form1.has_value(), true);
    if (form1) {
        InvokeResult r5 = inv.invokeMethod(*form1, "on_combo1_currentIndexChanged");
        expect_b("on_combo1_currentIndexChanged invoked", r5.ok, true);
        expect_b("combo handler body ran", umvpqt_mock::g_on_combo1_idx_changed >= 1, true);
    }

    // ---- analyzer god-mode enrichment (combo via invoke) ----
    Analyzer analyzer(*rd, &ex);
    AnalyzerOptions opt;
    opt.invoke = true;
    AnalysisReport rep = analyzer.analyze(opt);
    // find combo1 in allObjects
    const WidgetInfo* comboInfo = nullptr;
    for (const WidgetInfo& o : rep.allObjects)
        if (o.objectName == "combo1") { comboInfo = &o; break; }
    expect_b("combo1 in report", comboInfo != nullptr, true);
    if (comboInfo) {
        expect_i("combo currentIndex (invoke mode)", comboInfo->comboCurrentIndex, 1);
        expect_s("combo currentText (invoke mode)", comboInfo->comboCurrentText, "B");
        expect_i("combo confidence (invoke mode)", comboInfo->comboConfidence, 100);
        expect_i("combo items (invoke mode)", (long long)comboInfo->comboItems.size(), 3);
    }
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("[%s] test_invoke: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
