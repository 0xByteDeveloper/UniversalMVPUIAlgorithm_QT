// UMVPQT GOD STATE — CLI (umvpqt_cli)
// ============================================================================
//  Kullanim (XPRO CLI tarzi):
//    umvpqt_cli --list                       surec listesi
//    umvpqt_cli --pid N                      surec sec + analiz (interaktif ozet)
//    umvpqt_cli --pid N --json r.json --txt r.txt --asm-dir asm/
//    umvpqt_cli --name demo_qt_app           isimle sec
//    umvpqt_cli --pid N --no-live            sadece kod analizi
//    umvpqt_cli --pid N --no-code            sadece bellek taramasi
//    umvpqt_cli --pid N --no-text-decode     metin cozumleme kapali
//    umvpqt_cli --pid N --monitor --interval 500 --count 10
// ============================================================================
#include "umvpqt/analyzer.h"
#include "umvpqt/report.h"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

using namespace umvpqt;

static void printUsage() {
    printf("UMVPQT GOD STATE CLI — Qt MVP UI Algorithm (UniversalMVPUIAlgorithm_QT)\n"
           "  --list                 surec listesini goster\n"
           "  --pid N                surec sec\n"
           "  --name X               isimle surec sec\n"
           "  --json FILE            JSON rapor yaz\n"
           "  --txt FILE             text rapor yaz\n"
           "  --asm-dir DIR          handler .asm dump dizini\n"
           "  --no-live              bellek taramasi KAPALI\n"
           "  --no-code              disasm/metacall KAPALI\n"
           "  --no-text-decode       QString cozumleme KAPALI\n"
           "  --monitor              izleme modu (diff)\n"
           "  --interval MS          izleme araligi (ms, min 200)\n"
           "  --count N              izleme turu sayisi\n");
}

int main(int argc, char** argv) {
    uint64_t pid = 0;
    std::string name, jsonFile, txtFile, asmDir;
    bool monitor = false;
    int intervalMs = 1000, count = 0;
    umvpqt::AnalyzeOptions opt;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--list")) {
            for (auto& e : listProcesses())
                printf("%6llu  %s\n", (unsigned long long)e.pid, e.name.c_str());
            return 0;
        } else if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            pid = strtoull(argv[++i], nullptr, 10);
        } else if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            name = argv[++i];
        } else if (!strcmp(argv[i], "--json") && i + 1 < argc) {
            jsonFile = argv[++i];
        } else if (!strcmp(argv[i], "--txt") && i + 1 < argc) {
            txtFile = argv[++i];
        } else if (!strcmp(argv[i], "--asm-dir") && i + 1 < argc) {
            asmDir = argv[++i];
        } else if (!strcmp(argv[i], "--no-live")) opt.live = false;
        else if (!strcmp(argv[i], "--no-code")) opt.code = false;
        else if (!strcmp(argv[i], "--no-text-decode")) opt.textDecode = false;
        else if (!strcmp(argv[i], "--monitor")) monitor = true;
        else if (!strcmp(argv[i], "--interval") && i + 1 < argc) intervalMs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc) count = atoi(argv[++i]);
        else { printUsage(); return 1; }
    }
    if (intervalMs < 200) intervalMs = 200;
    opt.asmDir = asmDir;

    std::unique_ptr<IProcessReader> proc;
    if (pid) proc = openProcess(pid);
    else if (!name.empty()) proc = openProcessByName(name);
    if (!proc) { fprintf(stderr, "Surec acilamadi (pid=%llu name=%s)\n", (unsigned long long)pid, name.c_str()); return 2; }

    printf("[*] Surec: %llu (%s)\n", (unsigned long long)proc->pid(), proc->name().c_str());

    Analyzer analyzer(std::move(proc));
    AnalysisReport rpt = analyzer.run(opt);

    if (!rpt.qt.present) {
        printf("[-] Bu surecte Qt bulunamadi.\n");
        if (!jsonFile.empty()) { FILE* f = fopen(jsonFile.c_str(), "w"); if (f) { fputs("{\"qt\":{\"present\":false}}\n", f); fclose(f); } }
        return 3;
    }
    printf("[+] Qt tespit edildi: %s (surum %s) — %s\n",
           rpt.qt.era == QtEra::Qt6 ? "Qt6" : rpt.qt.era == QtEra::Qt5 ? "Qt5" : "Qt4",
           rpt.qt.version.c_str(), rpt.qt.detection.c_str());
    printf("[*] %s\n", Report::summary(rpt).c_str());

    std::string tree = Report::textTree(rpt);
    if (!txtFile.empty()) {
        FILE* f = fopen(txtFile.c_str(), "w");
        if (f) { fwrite(tree.data(), 1, tree.size(), f); fclose(f); printf("[+] Text rapor: %s\n", txtFile.c_str()); }
    }
    std::string js = Report::json(rpt);
    if (!jsonFile.empty()) {
        FILE* f = fopen(jsonFile.c_str(), "w");
        if (f) { fwrite(js.data(), 1, js.size(), f); fclose(f); printf("[+] JSON rapor: %s\n", jsonFile.c_str()); }
    }
    if (txtFile.empty()) fwrite(tree.data(), 1, tree.size(), stdout);

    // ---- monitor modu ----
    if (monitor) {
        printf("[*] Monitor modu (%d ms aralik%s) — Ctrl+C ile durdur\n",
               intervalMs, count > 0 ? std::string(", " + std::to_string(count) + " tur").c_str() : ", surekli");
        for (int t = 0; count == 0 || t < count; t++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            std::string diff = analyzer.monitorStep(rpt, opt);
            if (!diff.empty()) {
                printf("--- DIFF (tur %d) ---\n%s", t, diff.c_str());
                fflush(stdout);
            }
        }
    }
    return 0;
}
