// =============================================================================
// UMVP-QT // cli/main.cpp — umvpqt_cli: GOD STATE Qt UI analiz CLI.
//   umvpqt_cli                      interaktif: surec listesi + secim
//   umvpqt_cli --list
//   umvpqt_cli --pid 1234 --json r.json --txt r.txt --asm-dir asm/
//   umvpqt_cli --name app.exe --family qt6
//   umvpqt_cli --pid 1234 --click button1        "button1'e bas"
//   umvpqt_cli --pid 1234 --invoke button1.click()
//   umvpqt_cli --pid 1234 --emit button1.clicked
//   --no-live    sadece kod analizi
//   --no-code    sadece canli bellek
//   --no-invoke  cagirma motorunu kapat
// =============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "umvpqt/analyzer.h"
#include "umvpqt/process.h"
#include "umvpqt/qt_invoke.h"
#include "umvpqt/qt_scan.h"
#include "umvpqt/report.h"

using namespace umvpqt;

namespace {

void usage() {
    std::printf(
        "UMVP-QT // UniversalMVPUIAlgorithm_QT — GOD STATE QT UI ANALYSIS\n"
        "kullanim:\n"
        "  umvpqt_cli [--list | --pid N | --name exe]\n"
        "            [--json dosya] [--txt dosya] [--asm-dir dizin]\n"
        "            [--family qt5|qt6] [--no-live] [--no-code] [--no-invoke]\n"
        "            [--click nesneAdi] [--invoke nesneAdi.method]\n"
        "            [--emit nesneAdi.signal]\n");
}

struct Args {
    bool list = false, havePid = false;
    uint32_t pid = 0;
    std::string name, json, txt, asmDir;
    QtFamily family = QtFamily::Unknown;
    bool live = true, code = true, invoke = true;
    std::string click, invokeSpec, emitSpec;
};

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (s == "--list") a.list = true;
        else if (s == "--pid") { a.pid = (uint32_t)strtoul(next().c_str(), nullptr, 10); a.havePid = true; }
        else if (s == "--name") a.name = next();
        else if (s == "--json") a.json = next();
        else if (s == "--txt") a.txt = next();
        else if (s == "--asm-dir") a.asmDir = next();
        else if (s == "--family") {
            std::string f = next();
            if (f == "qt5") a.family = QtFamily::Qt5;
            else if (f == "qt6") a.family = QtFamily::Qt6;
        }
        else if (s == "--no-live") a.live = false;
        else if (s == "--no-code") a.code = false;
        else if (s == "--no-invoke") a.invoke = false;
        else if (s == "--click") a.click = next();
        else if (s == "--invoke") a.invokeSpec = next();
        else if (s == "--emit") a.emitSpec = next();
        else if (s == "-h" || s == "--help") { usage(); std::exit(0); }
        else { std::fprintf(stderr, "bilinmeyen arguman: %s\n", s.c_str()); usage(); std::exit(2); }
    }
    return a;
}

} // namespace

int main(int argc, char** argv) {
    Args a = parse(argc, argv);

    if (a.list || (!a.havePid && a.name.empty())) {
        auto procs = list_processes();
        std::printf("PID      AD\n");
        std::printf("-------- ----------------------------------------\n");
        for (const ProcessInfo& p : procs)
            std::printf("%-8u %s\n", p.pid, p.name.c_str());
        if (!a.list && procs.empty()) {
            std::printf("(surec yok — Linux /proc; Windows build Toolhelp kullanir)\n");
            return 0;
        }
        if (!a.list) {
            std::printf("PID sec: ");
            unsigned pid = 0;
            if (std::scanf("%u", &pid) != 1) return 0;
            a.pid = pid;
            a.havePid = true;
        } else return 0;
    }

    std::unique_ptr<IProcessReader> reader =
        a.havePid ? open_process_by_pid(a.pid)
                  : open_process_by_name(a.name);
    if (!reader) {
        std::fprintf(stderr, "surec acilamadi (pid=%u name=%s)\n", a.pid, a.name.c_str());
        return 1;
    }

    // invoke executor: Windows remote thread / Linux direct (real processes only
    // on Windows; on Linux the posix reader exposes /proc mem — reads work, calls
    // require a ptrace-based executor, listed as roadmap).
    IRemoteExecutor* executor = nullptr;

    Analyzer analyzer(*reader, executor);
    AnalyzerOptions opt;
    opt.live = a.live;
    opt.code = a.code;
    opt.invoke = a.invoke && executor != nullptr;
    opt.familyOverride = a.family;
    AnalysisReport rep = analyzer.analyze(opt);

    std::string text = report_text(rep);
    std::fwrite(text.data(), 1, text.size(), stdout);
    if (!a.txt.empty()) {
        FILE* f = std::fopen(a.txt.c_str(), "wb");
        if (f) { std::fwrite(text.data(), 1, text.size(), f); std::fclose(f); }
    }
    if (!a.json.empty()) {
        std::string js = report_json(rep);
        FILE* f = std::fopen(a.json.c_str(), "wb");
        if (f) { std::fwrite(js.data(), 1, js.size(), f); std::fclose(f); }
    }
    if (!a.asmDir.empty()) {
        auto files = write_asm_dir(rep, a.asmDir);
        std::fprintf(stderr, "asm: %zu handler dosyasi -> %s\n", files.size(), a.asmDir.c_str());
    }

    // ---- god-mode actions on the live report ----
    if (!a.click.empty() || !a.invokeSpec.empty() || !a.emitSpec.empty()) {
        const QtLayout* L = layout_for(rep.qt.family);
        if (!L || !executor) {
            std::fprintf(stderr, "cagirma motoru bu platformda devre disi (read-only)\n");
            return 0;
        }
        InvokeEngine inv(*reader, *L, executor);
        ObjectScanner scanner(*reader, *L);
        auto fire = [&](const std::string& objectName, const std::string& what) {
            for (const WidgetInfo& w : rep.allObjects) {
                if (w.objectName != objectName) continue;
                auto node = scanner.parseObjectNode(w.object);
                if (!node) continue;
                InvokeResult r;
                if (what == "click") r = inv.click(*node);
                else if (what == "gui-click") r = inv.guiClick(*node);
                else if (what == "emit:clicked") r = inv.emitSignal(*node, "clicked");
                std::printf("invoke: ok=%d str=%s detay=%s\n", r.ok ? 1 : 0,
                            r.strategy.c_str(), r.detail.c_str());
                return;
            }
            std::fprintf(stderr, "nesne bulunamadi: %s\n", objectName.c_str());
        };
        if (!a.click.empty()) fire(a.click, "click");
        if (!a.emitSpec.empty()) fire(a.emitSpec, "emit:clicked");
        if (!a.invokeSpec.empty()) {
            // form: nesneAdi.method
            std::string spec = a.invokeSpec;
            size_t dot = spec.find('.');
            if (dot != std::string::npos) {
                std::string objName = spec.substr(0, dot);
                std::string method = spec.substr(dot + 1);
                if (method.size() >= 2 && method.substr(method.size() - 2) == "()")
                    method = method.substr(0, method.size() - 2);
                for (const WidgetInfo& w : rep.allObjects) {
                    if (w.objectName != objName) continue;
                    auto node = scanner.parseObjectNode(w.object);
                    if (!node) continue;
                    InvokeResult r = inv.invokeMethod(*node, method);
                    std::printf("invoke %s.%s: ok=%d str=%s detay=%s\n",
                                objName.c_str(), method.c_str(), r.ok ? 1 : 0,
                                r.strategy.c_str(), r.detail.c_str());
                    break;
                }
            } else std::fprintf(stderr, "--invoke bicimi: nesneAdi.method()\n");
        }
    }
    return 0;
}
