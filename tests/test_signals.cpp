// =============================================================================
// UMVP-QT // tests/test_signals.cpp — connection graph scan (olay VAR/YOK):
//   * button1 clicked -> Form1::on_button1_clicked   (method connection)
//   * button2 clicked -> lambda                      (functor connection)
//   * check1 toggled  -> Form1::on_check1_toggled    (method connection)
//   * combo1 currentIndexChanged -> YOK              (event-less object)
//   * label1 -> YOK
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "mock/mock_qt.h"
#include "umvpqt/qt_meta.h"
#include "umvpqt/qt_scan.h"
#include "umvpqt/qt_signals.h"

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
    IProcessReader* rd = img.reader();

    ObjectScanner scanner(*rd, L);
    auto b1 = scanner.parseObjectNode(w.button1);
    auto b2 = scanner.parseObjectNode(w.button2);
    auto c1 = scanner.parseObjectNode(w.combo1);
    auto l1 = scanner.parseObjectNode(w.label1);
    auto ck = scanner.parseObjectNode(w.check1);
    expect_b("button1 parses", b1.has_value(), true);
    if (!b1) return;
    expect_b("button2 parses", b2.has_value(), true);
    expect_b("combo1 parses", c1.has_value(), true);

    ConnectionScanner cs(*rd, L);
    auto conns1 = cs.outgoing(*b1);
    expect_b("button1 has exactly 1 connection", conns1.size() == 1, true);
    if (!conns1.empty()) {
        const ConnectionInfo& ci = conns1[0];
        expect_s("button1 signal name", ci.signalName, "clicked");
        expect_s("button1 slot name", ci.slotName, "on_button1_clicked");
        expect_s("button1 slot owner", ci.slotOwnerClass, "Form1");
        expect_s("button1 type", ci.connectionType, "direct");
        expect_b("button1 not functor", ci.isSlotObject, false);
        expect_b("button1 receiver is Form1", ci.receiver == w.form1, true);
        expect_b("button1 callFunction is Form1 metacall",
                 ci.callFunction != 0 && rd->isExecutable(ci.callFunction), true);
    }

    auto conns2 = cs.outgoing(*b2);
    expect_b("button2 has exactly 1 connection", conns2.size() == 1, true);
    if (!conns2.empty()) {
        const ConnectionInfo& ci = conns2[0];
        expect_s("button2 signal name", ci.signalName, "clicked");
        expect_b("button2 is functor", ci.isSlotObject, true);
        expect_b("button2 slotObject valid", ci.slotObject != 0, true);
    }

    auto connsC = cs.outgoing(*c1);
    expect_b("combo1 has NO connections (olay yok)", connsC.empty(), true);

    auto connsL = cs.outgoing(*l1);
    expect_b("label1 has NO connections", connsL.empty(), true);

    auto connsK = cs.outgoing(*ck);
    expect_b("check1 has exactly 1 connection", connsK.size() == 1, true);
    if (!connsK.empty()) {
        expect_s("check1 signal name", connsK[0].signalName, "toggled");
        expect_s("check1 slot name", connsK[0].slotName, "on_check1_toggled");
    }

    // functor handler resolution
    if (!conns2.empty()) {
        DiscoveredObject fakeReceiver;   // functor path doesn't need receiver meta
        auto h = cs.resolveHandler(conns2[0], fakeReceiver);
        expect_b("button2 handler resolved", h.has_value(), true);
        if (h) {
            expect_b("button2 handler range valid", h->end > h->base, true);
            expect_s("button2 via", h->viaKind, "slot-object");
        }
    }
    // method handler resolution via deep disassembly of Form1 metacall
    if (!conns1.empty()) {
        auto receiver = scanner.parseObjectNode(w.form1);
        auto h = cs.resolveHandler(conns1[0], *receiver);
        expect_b("button1 handler resolved via disasm", h.has_value(), true);
        if (h) {
            expect_s("button1 handler name", h->methodName, "on_button1_clicked");
            expect_s("button1 handler owner", h->ownerClass, "Form1");
            expect_b("button1 handler entry in exec", rd->isExecutable(h->entry), true);
            expect_b("button1 handler range valid", h->end > h->base, true);
            expect_b("button1 disasm non-empty", h->disasm.instructionCount > 0, true);
        }
    }
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("[%s] test_signals: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
