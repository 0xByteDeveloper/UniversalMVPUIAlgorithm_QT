// =============================================================================
// UMVP-QT // tests/demo_main.cpp — GOD STATE demo (integration showcase).
// Builds the synthetic Qt process image (Qt5 AND Qt6 ABI), runs the FULL
// analyzer pipeline (memory scan -> meta objects -> connection graph ->
// deep disassembly -> invoke god mode) and prints the reports + live invoke
// results. This is the Linux-native equivalent of the original UMVP's Wine
// integration test.
// =============================================================================
#include <cstdio>
#include <string>

#include "mock/mock_executor.h"
#include "mock/mock_qt.h"
#include "umvpqt/analyzer.h"
#include "umvpqt/report.h"

using namespace umvpqt;
using umvpqt_mock::MockImage;
using umvpqt_mock::MockRemoteExecutor;

static void run_family(QtFamily fam) {
    MockImage img(fam);
    auto w = img.buildWorld();
    MockRemoteExecutor executor;

    std::printf("\n================ %s =================\n",
                fam == QtFamily::Qt5 ? "Qt 5.15 ABI" : "Qt 6.8 ABI");

    Analyzer analyzer(*img.reader(), &executor);
    AnalyzerOptions opt;
    opt.invoke = true;   // god mode: property reads + invocations through metacall
    AnalysisReport rep = analyzer.analyze(opt);
    std::printf("%s", report_text(rep).c_str());

    // ---- live god-mode actions on button1 ---------------------------------
    const QtLayout* L = layout_for(fam);
    ObjectScanner scanner(*img.reader(), *L);
    auto b1 = scanner.parseObjectNode(w.button1);
    auto c1 = scanner.parseObjectNode(w.combo1);
    if (b1 && c1) {
        InvokeEngine inv(*img.reader(), *L, &executor);
        std::printf("--- GOD MODE INVOKES (button1 / combo1) ------------\n");
        int before = umvpqt_mock::g_on_button1_clicked + umvpqt_mock::g_button_click_slot;
        InvokeResult r = inv.click(*b1);      // "button1'e bas"
        int after = umvpqt_mock::g_on_button1_clicked + umvpqt_mock::g_button_click_slot;
        std::printf("click(button1)      : ok=%d  fired=%d  [%s | %s]\n",
                    r.ok ? 1 : 0, after - before, r.strategy.c_str(), r.detail.c_str());
        auto txt = inv.readProperty(*b1, "text");
        std::printf("readProperty(text)  : \"%s\"\n",
                    txt ? txt->asString.c_str() : "<yok>");
        auto idx = inv.readProperty(*c1, "currentIndex");
        auto cnt = inv.readProperty(*c1, "count");
        std::printf("combo currentIndex  : %d / count=%d\n",
                    idx ? (int)idx->asInt : -1, cnt ? (int)cnt->asInt : -1);
        std::printf("combo items (itemText invoke): ");
        for (size_t i = 0; i < rep.allObjects.size(); ++i) {
            if (rep.allObjects[i].objectName != "combo1") continue;
            for (auto& it : rep.allObjects[i].comboItems)
                std::printf("%s|", it.c_str());
        }
        std::printf("\n");
    }
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("\n[DEMO OK] UMVP-QT tam boru hatti (bellek tarama + meta + baglanti + "
                "disassembly + invoke) iki Qt ailesinde de calisti.\n");
    return 0;
}
