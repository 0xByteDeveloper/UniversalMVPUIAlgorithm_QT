// UMVPQT GOD STATE — Agent (AI surucu protokolu)
// ============================================================================
//  Yapay zekanin UMVPQT'yi "bir uzvu gibi" kullanmasi icin JSON-lines
//  komut protokolu. Her komut satiri stdin'e JSON olarak yazilir, yanit
//  stdout'a tek JSON satiri olarak doner — agent dongusuz, stateful.
//
//  oturum:
//    uqt_agent --pid 1234                 (stdin/stdout JSON-lines)
//    uqt_agent --name vmprotect --allow-shell
//    uqt_agent --script senaryo.json      (tek atis + sonuc raporu)
//
//  komutlar (docs/AGENT.md'de tam referans):
//    attach, info, analyze, forms, tree, find, props, handlers,
//    click, check, setcombo, settext, selectrow, call,
//    rescan, wait, waitform, waitwidget, sh, script, quit
// ============================================================================
#pragma once
#include "types.h"
#include "analyzer.h"
#include "invoke.h"
#include "json.h"
#include <memory>
#include <string>

namespace umvpqt {

class Agent {
public:
    // allowShell: "sh" komutuna izin (senaryolarda dosya yeniden adlandirma)
    explicit Agent(bool allowShell = false) : allowShell_(allowShell) {}

    // JSON-lines REPL dondurur: 0 = normal kapanis
    int runREPL(std::istream& in, std::ostream& out);
    // script dosyasinin komut dizisini calistirir
    int runScriptFile(const std::string& path, std::ostream& out);

    // tek komut isle (dahili ve test icin public)
    Json execute(const Json& cmd);

private:
    // ---- yardimcilar ----
    bool ensureInvoker(Json& resp);
    const WidgetInfo* findWidget(const Json& j, std::string* err);
    const WidgetInfo* findWidgetInner(const Json& j, std::string* err, bool allowRescan);
    void refreshFormWidgetCache();   // V3.2: formları hedeflenebilir yapar
    Json widgetJson(const WidgetInfo& w, bool deep = false);
    Json formJson(const FormInfo& f, bool deep = false);

    // ---- komut isleyicileri (ok, hata) ----
    std::pair<bool,std::string> cmdAttach(const Json& j);
    std::pair<bool,std::string> cmdAnalyze(const Json& j);
    std::pair<bool,std::string> cmdForms(const Json& j);
    std::pair<bool,std::string> cmdTree(const Json& j);
    std::pair<bool,std::string> cmdFind(const Json& j);
    std::pair<bool,std::string> cmdProps(const Json& j);
    std::pair<bool,std::string> cmdHandlers(const Json& j);
    std::pair<bool,std::string> cmdClick(const Json& j);
    std::pair<bool,std::string> cmdCheck(const Json& j);
    std::pair<bool,std::string> cmdSetCombo(const Json& j);
    std::pair<bool,std::string> cmdSetText(const Json& j);
    std::pair<bool,std::string> cmdSelectRow(const Json& j);
    std::pair<bool,std::string> cmdCall(const Json& j);
    std::pair<bool,std::string> cmdRescan(const Json& j);
    std::pair<bool,std::string> cmdObjects(const Json& j);   // V3.3: nesne envanteri
    std::pair<bool,std::string> cmdWaitForm(const Json& j);
    std::pair<bool,std::string> cmdWaitWidget(const Json& j);
    std::pair<bool,std::string> cmdSh(const Json& j);
    std::pair<bool,std::string> cmdScript(const Json& j);

    // ---- V3.2: X11 giriş katmanı (wine hedefleri — Tier-1 dengi) ----
    std::pair<bool,std::string> cmdXKey(const Json& j);      // {"keysym":"F9"} / "Ctrl+F9"
    std::pair<bool,std::string> cmdXClick(const Json& j);    // {"x":..,"y":..,"button":1}
    std::pair<bool,std::string> cmdXType(const Json& j);     // {"text":"MovePlayer"}
    std::pair<bool,std::string> cmdXWindows(const Json& j);  // X pencere envanteri
    std::pair<bool,std::string> cmdQuit(const Json& j);

    // ---- durum ----
    std::unique_ptr<Analyzer> analyzer_;
    std::unique_ptr<IInvoker> invoker_;
    QtActor actor_;
    AnalysisReport report_;
    Json lastData_;
    std::vector<WidgetInfo> formWidgetCache_;   // V3.2: formlar hedeflenebilir
    bool analyzed_ = false;
    bool allowShell_ = false;
    bool quit_ = false;
    uint64_t cmdSeq_ = 0;
};

} // namespace umvpqt
