// UMVPQT GOD STATE — Agent uygulamasi (JSON-lines komut motoru)
// ============================================================================
#include "umvpqt/agent.h"
#include "umvpqt/invoke_x11.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <sstream>

namespace umvpqt {

// =====================================================================
//  yardimcilar
// =====================================================================
static std::string jaddr(Addr a) {
    char b[32];
    snprintf(b, sizeof(b), "0x%llx", (unsigned long long)a);
    return b;
}
static std::string jrange(Addr s, Addr e) {
    char b[48];
    snprintf(b, sizeof(b), "0x%llx-0x%llx", (unsigned long long)s, (unsigned long long)e);
    return b;
}
static std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}
static bool containsCI(const std::string& hay, const std::string& needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}

// =====================================================================
//  REPL
// =====================================================================
int Agent::runREPL(std::istream& in, std::ostream& out) {
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        Json cmd;
        if (!JsonParser::parse(line, cmd)) {
            Json resp = Json::mkObj();
            resp.set("ok", false);
            resp.set("err", "JSON cozumlenemedi: " + line.substr(0, 120));
            out << resp.dump() << "\n";
            out.flush();
            continue;
        }
        Json resp = execute(cmd);
        out << resp.dump() << "\n";
        out.flush();
        if (quit_) break;
    }
    // kapanista invoker'i temiz birak
    if (invoker_) {
        invoker_->pollPending();
        invoker_.reset();
    }
    return 0;
}

int Agent::runScriptFile(const std::string& path, std::ostream& out) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) {
        Json resp = Json::mkObj();
        resp.set("ok", false);
        resp.set("err", "script dosyasi acilamadi: " + path);
        out << resp.dump() << "\n";
        return 2;
    }
    std::string text;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    fclose(f);
    Json arr;
    if (!JsonParser::parse(text, arr) || !arr.isArr()) {
        // dizi degil — satir satir REPL olarak isle
        std::istringstream ss(text);
        return runREPL(ss, out);
    }
    for (auto& c : arr.arr) {
        Json resp = execute(c);
        out << resp.dump() << "\n";
        out.flush();
        if (quit_) break;
    }
    if (invoker_) {
        invoker_->pollPending();
        invoker_.reset();
    }
    return 0;
}

// =====================================================================
//  execute — dispatch
// =====================================================================
Json Agent::execute(const Json& cmd) {
    cmdSeq_++;
    std::string name = cmd.isObj() ? cmd["cmd"].asStr() : "";
    Json resp = Json::mkObj();
    resp.set("seq", (double)cmdSeq_);
    resp.set("cmd", name);
    bool ok = false;
    std::string err;
    lastData_ = Json::mkObj();

    if (name.empty()) {
        // {"_": "yorum"} satirlari — no-op (senaryo dosyalarinda yorum)
        ok = true;
        lastData_.set("comment", true);
    }
    else if (name == "attach")           { auto r = cmdAttach(cmd); ok = r.first; err = r.second; }
    else if (name == "analyze")     { auto r = cmdAnalyze(cmd); ok = r.first; err = r.second; }
    else if (name == "info") {
        if (analyzed_) {
            Json data = Json::mkObj();
            data.set("pid", (double)report_.pid);
            data.set("process", report_.processName);
            data.set("qt_era", report_.qt.era == QtEra::Qt6 ? "Qt6" :
                               report_.qt.era == QtEra::Qt5 ? "Qt5" :
                               report_.qt.era == QtEra::Qt4 ? "Qt4" : "?");
            data.set("qt_version", report_.qt.version);
            data.set("objects", (double)report_.totalQObjects);
            data.set("widgets", (double)report_.totalWidgets);
            data.set("forms", (double)report_.forms.size());
            data.set("classes", (double)report_.classes.size());
            data.set("connections", (double)report_.allConnections.size());
            lastData_ = data;
            ok = true;
        } else err = "once attach+analyze";
    }
    else if (name == "forms")       { auto r = cmdForms(cmd); ok = r.first; err = r.second; }
    else if (name == "tree")        { auto r = cmdTree(cmd); ok = r.first; err = r.second; }
    else if (name == "find")        { auto r = cmdFind(cmd); ok = r.first; err = r.second; }
    else if (name == "props")       { auto r = cmdProps(cmd); ok = r.first; err = r.second; }
    else if (name == "handlers")    { auto r = cmdHandlers(cmd); ok = r.first; err = r.second; }
    else if (name == "click")       { auto r = cmdClick(cmd); ok = r.first; err = r.second; }
    else if (name == "check")       { auto r = cmdCheck(cmd); ok = r.first; err = r.second; }
    else if (name == "setcombo")    { auto r = cmdSetCombo(cmd); ok = r.first; err = r.second; }
    else if (name == "settext")     { auto r = cmdSetText(cmd); ok = r.first; err = r.second; }
    else if (name == "selectrow")   { auto r = cmdSelectRow(cmd); ok = r.first; err = r.second; }
    else if (name == "call")        { auto r = cmdCall(cmd); ok = r.first; err = r.second; }
    else if (name == "rescan")       { auto r = cmdRescan(cmd); ok = r.first; err = r.second; }
    else if (name == "objects")     { auto r = cmdObjects(cmd); ok = r.first; err = r.second; }
    else if (name == "wait") {
        int ms = (int)cmd["ms"].asNum(300);
        if (invoker_) invoker_->pollPending();
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        ok = true;
    }
    else if (name == "waitform")    { auto r = cmdWaitForm(cmd); ok = r.first; err = r.second; }
    else if (name == "waitwidget")  { auto r = cmdWaitWidget(cmd); ok = r.first; err = r.second; }
    else if (name == "sh")          { auto r = cmdSh(cmd); ok = r.first; err = r.second; }
    else if (name == "script")      { auto r = cmdScript(cmd); ok = r.first; err = r.second; }
    else if (name == "xkey")       { auto r = cmdXKey(cmd); ok = r.first; err = r.second; }
    else if (name == "xclick")     { auto r = cmdXClick(cmd); ok = r.first; err = r.second; }
    else if (name == "xtype")      { auto r = cmdXType(cmd); ok = r.first; err = r.second; }
    else if (name == "xwindows")   { auto r = cmdXWindows(cmd); ok = r.first; err = r.second; }
    else if (name == "quit")        { auto r = cmdQuit(cmd); ok = r.first; err = r.second; }
    else {
        err = "bilinmeyen komut: '" + name + "' (bkz. docs/AGENT.md)";
    }

    resp.set("ok", ok);
    if (!err.empty()) resp.set("err", err);
    else resp.set("data", lastData_);
    return resp;
}

// =====================================================================
//  baglanti / analiz kurulumu
// =====================================================================
bool Agent::ensureInvoker(Json& resp) {
    if (!invoker_) {
        invoker_ = createInvoker(analyzer_->proc());
        if (!invoker_) { resp.set("err", "invoke motoru kurulamadi (izin?)"); return false; }
        actor_.proc = &analyzer_->proc();
        actor_.mt = &analyzer_->modules();
        actor_.L = &analyzer_->layouts();
        actor_.reg = &analyzer_->registry();
        actor_.inv = invoker_.get();
        actor_.defaultTimeoutMs = 5000;

        // V3.2 — wine/PE hedef tespiti: modül tablosunda .exe/.dll PE modülü
        // varsa hedefteki kod Microsoft x64 ABI ile çağrılır (rcx/rdx/r8/r9).
        // (Linux ELF hedefler SysV ile kalır — anahtar kapalı.)
        bool winePE = false;
        for (auto& m : analyzer_->modules().modules()) {
            std::string n = m.name;
            for (auto& c : n) c = (char)::tolower((unsigned char)c);
            if (n.size() > 4) {
                std::string ext = n.substr(n.size() - 4);
                if (ext == ".exe" || ext == ".dll") { winePE = true; break; }
            }
        }
        if (winePE) invoker_->setWin64Convention(true);
    }
    return true;
}

// =====================================================================
//  komutlar
// =====================================================================
std::pair<bool,std::string> Agent::cmdAttach(const Json& j) {
    uint64_t pid = 0;
    std::string name = j["name"].asStr();
    if (j["pid"].isNum()) pid = (uint64_t)j["pid"].asNum();
    else if (j["pid"].isStr() && !parseAddr(j["pid"].asStr(), pid)) pid = 0;

    analyzer_.reset();
    invoker_.reset();
    analyzed_ = false;
    report_ = AnalysisReport();

    std::unique_ptr<IProcessReader> proc;
    if (pid) proc = openProcess(pid);
    else if (!name.empty()) proc = openProcessByName(name);
    if (!proc) return { false, pid ? "surec acilamadi pid=" + std::to_string(pid)
                                   : "surec bulunamadi: " + name };

    analyzer_ = std::make_unique<Analyzer>(std::move(proc));
    lastData_ = Json::mkObj();
    lastData_.set("pid", (double)analyzer_->proc().pid());
    lastData_.set("name", analyzer_->proc().name());
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdAnalyze(const Json& j) {
    (void)j;
    if (!analyzer_) return { false, "once attach" };
    AnalyzeOptions opt;
    report_ = analyzer_->run(opt);
    if (!report_.qt.present) return { false, "hedefte Qt tespit edilemedi" };
    analyzed_ = true;
    refreshFormWidgetCache();   // V3.2: formlar hedeflenebilir
    lastData_ = Json::mkObj();
    lastData_.set("qt_version", report_.qt.version);
    lastData_.set("era", report_.qt.era == QtEra::Qt6 ? "Qt6" :
                       report_.qt.era == QtEra::Qt5 ? "Qt5" : "Qt4");
    lastData_.set("objects", (double)report_.totalQObjects);
    lastData_.set("widgets", (double)report_.totalWidgets);
    lastData_.set("forms", (double)report_.forms.size());
    lastData_.set("classes", (double)report_.classes.size());
    lastData_.set("connections", (double)report_.allConnections.size());
    return { true, "" };
}

Json Agent::formJson(const FormInfo& f, bool deep) {
    Json o = Json::mkObj();
    o.set("address", jaddr(f.address));
    o.set("class", f.className);
    o.set("name", f.objectName);
    o.set("title", f.windowTitle);
    o.set("visible", f.visible);
    Json rect = Json::mkObj();
    rect.set("x", (double)f.x); rect.set("y", (double)f.y);
    rect.set("w", (double)f.w); rect.set("h", (double)f.h);
    o.set("rect", rect);
    o.set("widgetCount", (double)f.widgetCount);
    if (deep) {
        Json ws = Json::mkArr();
        for (auto& w : f.widgets) ws.push(widgetJson(w, false));
        o.set("widgets", ws);
    }
    return o;
}

Json Agent::widgetJson(const WidgetInfo& w, bool deep) {
    Json o = Json::mkObj();
    o.set("address", jaddr(w.address));
    o.set("class", w.className);
    o.set("name", w.objectName);
    if (!w.text.empty()) o.set("text", w.text);
    if (!w.windowTitle.empty()) o.set("title", w.windowTitle);
    if (!w.editText.empty()) o.set("edit", w.editText);
    if (!w.toolTip.empty()) o.set("tooltip", w.toolTip);
    Json rect = Json::mkObj();
    rect.set("x", (double)w.x); rect.set("y", (double)w.y);
    rect.set("w", (double)w.w); rect.set("h", (double)w.h);
    rect.set("gx", (double)w.globalX); rect.set("gy", (double)w.globalY);
    o.set("rect", rect);
    o.set("visible", w.visible);
    o.set("parent", jaddr(w.parent));
    // combobox degerleri
    if (!w.comboItems.empty()) {
        Json items = Json::mkArr();
        for (auto& s : w.comboItems) items.push(s);
        o.set("comboItems", items);
        o.set("comboIndex", (double)w.comboCurrentIndex);
        o.set("comboValue", w.comboCurrentText);
    }
    // event ozeti
    o.set("hasClickHandler", w.hasClickHandler);
    if (!w.clickHandlerName.empty()) o.set("clickHandler", w.clickHandlerName);
    if (deep) {
        Json conns = Json::mkArr();
        for (auto& c : w.connections) {
            Json cj = Json::mkObj();
            cj.set("signal", c.signalName);
            cj.set("slot", c.slotSignature);
            cj.set("sender", jaddr(c.sender));
            cj.set("receiver", jaddr(c.receiver));
            if (c.slotCode) cj.set("slotCode", jaddr(c.slotCode));
            conns.push(cj);
        }
        o.set("connections", conns);
        Json hs = Json::mkArr();
        for (auto& h : w.handlers) {
            Json hj = Json::mkObj();
            hj.set("kind", h.kind);
            hj.set("name", h.name);
            hj.set("range", jrange(h.start, h.end));
            hj.set("module", h.module);
            hs.push(hj);
        }
        o.set("handlers", hs);
    }
    return o;
}

std::pair<bool,std::string> Agent::cmdForms(const Json& j) {
    (void)j;
    if (!analyzer_ || !analyzed_) return { false, "once attach+analyze" };
    Json arr = Json::mkArr();
    bool deep = j["deep"].asBool(false);
    for (auto& f : report_.forms) arr.push(formJson(f, deep));
    lastData_ = Json::mkObj();
    lastData_.set("forms", arr);
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdTree(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    int idx = (int)j["form"].asNum(0);
    if (idx < 0 || idx >= (int)report_.forms.size())
        return { false, "form indeksi gecersiz (0.." + std::to_string(report_.forms.size()-1) + ")" };
    lastData_ = formJson(report_.forms[idx], true);
    return { true, "" };
}

// ---- widget bulucu: addr | name | text | class (form kapsami opsiyonel) ----
// rescan=true: bulunamazsa bir kez rescan yapip tekrar dene
const WidgetInfo* Agent::findWidget(const Json& j, std::string* err) {
    return findWidgetInner(j, err, true);
}

const WidgetInfo* Agent::findWidgetInner(const Json& j, std::string* err, bool allowRescan) {
    // V3.2 — FORMLARIN KENDİLERİ de hedeflenebilir (MainWindow::addFunction
    // gibi form-slots çağrılarında "widget bulunamadı" körleri bu yüzden olur).
    // formWidgetCache_ analyze/rescan sonrası report_.forms'tan üretilir.
    if (!formWidgetCache_.empty()) {
        Addr want = 0;
        if (j.has("addr") || j.has("address")) {
            if (j["addr"].isNum() || j["address"].isNum())
                want = (Addr)(j.has("addr") ? j["addr"].asNum() : j["address"].asNum());
            else {
                std::string a = j.has("addr") ? j["addr"].asStr() : j["address"].asStr();
                if (!parseAddr(a, want)) { if (err) *err = "adres cozumlenemedi: " + a; return nullptr; }
            }
        }
        std::string name = j["name"].asStr();
        std::string text = j["text"].asStr();
        std::string cls  = j["class"].asStr();
        for (auto& w : formWidgetCache_) {
            if (want && w.address != want) continue;
            if (!name.empty() && w.objectName != name) continue;
            if (!text.empty() && !containsCI(w.text, text) &&
                !containsCI(w.windowTitle, text) && !containsCI(w.objectName, text)) continue;
            if (!cls.empty() && !containsCI(w.className, cls)) continue;
            return &w;
        }
    }
    Addr want = 0;
    if (j.has("addr") || j.has("address")) {
        if (j["addr"].isNum() || j["address"].isNum())
            want = (Addr)(j.has("addr") ? j["addr"].asNum() : j["address"].asNum());
        else {
            std::string a = j.has("addr") ? j["addr"].asStr() : j["address"].asStr();
            if (!parseAddr(a, want)) { if (err) *err = "adres cozumlenemedi: " + a; return nullptr; }
        }
    }
    std::string name = j["name"].asStr();
    std::string text = j["text"].asStr();
    std::string cls  = j["class"].asStr();
    int formScope = (int)j["form"].asNum(-1);

    for (size_t fi = 0; fi < report_.forms.size(); fi++) {
        if (formScope >= 0 && (int)fi != formScope) continue;
        auto& f = report_.forms[fi];
        for (auto& w : f.widgets) {
            if (want && w.address != want) continue;
            if (!name.empty() && w.objectName != name) continue;
            if (!text.empty() && !containsCI(w.text, text) &&
                !containsCI(w.windowTitle, text) && !containsCI(w.objectName, text)) continue;
            if (!cls.empty() && !containsCI(w.className, cls)) continue;
            return &w;
        }
    }
    // bulunamadi — bir kez rescan dene (dinamik yeni widget olabilir)
    if (allowRescan && j["rescan"].asBool(true)) {
        cmdRescan(Json::mkObj());
        return findWidgetInner(j, err, false);
    }
    if (err) *err = "widget bulunamadi";
    return nullptr;
}

// ---------------------------------------------- V3.2 form-cache -------
// report_.forms kayitlarini WidgetInfo olarak kopyalar — findWidgetInner'in
// ilk turunda formlar (MainWindow, QDialog'lar) da adres/isim/sınıf ile
// hedeflenebilir olur.
void Agent::refreshFormWidgetCache() {
    formWidgetCache_.clear();
    formWidgetCache_.reserve(report_.forms.size());
    for (auto& f : report_.forms) {
        WidgetInfo w;
        w.address = f.address;
        w.className = f.className;
        w.objectName = f.objectName;
        w.windowTitle = f.windowTitle;
        w.x = f.x; w.y = f.y; w.w = f.w; w.h = f.h;
        w.visible = f.visible;
        w.topLevel = true;
        formWidgetCache_.push_back(std::move(w));
    }
}

std::pair<bool,std::string> Agent::cmdFind(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    Json out = Json::mkArr();
    std::string cls = j["class"].asStr();
    std::string text = j["text"].asStr();
    std::string name = j["name"].asStr();
    for (auto& f : report_.forms) {
        for (auto& w : f.widgets) {
            if (!cls.empty() && !containsCI(w.className, cls)) continue;
            if (!text.empty() && !containsCI(w.text, text) && !containsCI(w.editText, text)) continue;
            if (!name.empty() && !containsCI(w.objectName, name)) continue;
            Json e = widgetJson(w, false);
            e.set("form", f.windowTitle.empty() ? f.className : f.windowTitle);
            out.push(e);
        }
    }
    lastData_ = Json::mkObj();
    lastData_.set("matches", out);
    lastData_.set("count", (double)out.arr.size());
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdProps(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    lastData_ = widgetJson(*w, true);
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdHandlers(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json o = Json::mkObj();
    o.set("address", jaddr(w->address));
    o.set("class", w->className);
    o.set("hasClickHandler", w->hasClickHandler);
    Json hs = Json::mkArr();
    for (auto& h : w->handlers) {
        Json hj = Json::mkObj();
        hj.set("kind", h.kind);
        hj.set("name", h.name);
        hj.set("start", jaddr(h.start));
        hj.set("end", jaddr(h.end));
        hj.set("range", jrange(h.start, h.end));
        hj.set("module", h.module);
        hs.push(hj);
    }
    o.set("handlers", hs);
    Json conns = Json::mkArr();
    for (auto& c : w->connections) {
        Json cj = Json::mkObj();
        cj.set("signal", c.signalName);
        cj.set("slot", c.slotSignature);
        if (c.slotCode) cj.set("slotCode", jaddr(c.slotCode));
        conns.push(cj);
    }
    o.set("connections", conns);
    lastData_ = o;
    return { true, "" };
}

// =====================================================================
//  AKSIYON komutlari (invoke)
// =====================================================================
static Json actionResult(const std::string& what, Addr addr, const RemoteCallResult& r) {
    Json o = Json::mkObj();
    o.set("action", what);
    o.set("target", jaddr(addr));
    o.set("invoked", r.ok || r.pending);
    o.set("pending", r.pending);
    if (r.ok) o.set("ret", jaddr(r.ret));
    if (!r.error.empty()) o.set("note", r.error);
    return o;
}

std::pair<bool,std::string> Agent::cmdClick(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };
    int timeout = (int)j["timeout"].asNum(5000);
    RemoteCallResult r = actor_.click(w->address, timeout);
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult("click", w->address, r);
    if (!r.ok && !r.pending) return { false, "click cagrilmadi: " + r.error };
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdCheck(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };
    bool on = j["value"].asBool(true);
    RemoteCallResult r = actor_.setChecked(w->address, on);
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult("setChecked", w->address, r);
    if (!r.ok && !r.pending) return { false, r.error };
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdSetCombo(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };

    int index = -1;
    if (j["index"].isNum()) index = (int)j["index"].asNum(-1);
    std::string val = j["value"].asStr();
    if (index < 0 && !val.empty()) {
        for (size_t i = 0; i < w->comboItems.size(); i++)
            if (containsCI(w->comboItems[i], val)) { index = (int)i; break; }
        if (index < 0)
            return { false, "combobox'ta boyle bir deger yok: '" + val +
                    "' (comboItems'a bakin)" };
    }
    if (index < 0) return { false, "index veya value verilmeli" };
    RemoteCallResult r = actor_.setComboIndex(w->address, index);
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult("setCurrentIndex", w->address, r);
    if (!r.ok && !r.pending) return { false, r.error };
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdSetText(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };
    std::string value = j["value"].asStr();
    if (value.empty()) return { false, "value verilmeli" };
    RemoteCallResult r = actor_.setText(w->address, value);
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult("setText", w->address, r);
    if (!r.ok && !r.pending) return { false, r.error };
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdSelectRow(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };
    int row = (int)j["row"].asNum(-1);
    if (row < 0) {
        // item metniyle satir bul (combo okuma + QListWidget icin bilinen
        // satir sayisi raporlanir; simdi row parametresi onerilir)
        return { false, "row verilmeli (item metniyle arama: list modelleri "
                        "QListWidget'ta QListModel — row kullanin)" };
    }
    RemoteCallResult r = actor_.selectRow(w->address, row);
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult("setCurrentRow", w->address, r);
    if (!r.ok && !r.pending) return { false, r.error };
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdCall(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string err;
    const WidgetInfo* w = findWidget(j, &err);
    if (!w) return { false, err.empty() ? "widget bulunamadi" : err };
    Json resp;
    if (!ensureInvoker(resp)) return { false, resp["err"].asStr("invoker yok") };
    std::string fn = j["fn"].asStr();
    if (fn.empty()) return { false, "fn verilmeli" };
    uint64_t a1 = (uint64_t)j["a1"].asNum(0);
    if (j["a1"].isStr()) parseAddr(j["a1"].asStr(), a1);
    RemoteCallResult r;
    if (fn == "click")                 r = actor_.click(w->address);
    else if (fn == "setChecked")        r = actor_.setChecked(w->address, j["value"].asBool(true));
    else if (fn == "setCurrentIndex")   r = actor_.setComboIndex(w->address, (int)j["index"].asNum((double)a1));
    else if (fn == "setCurrentRow")     r = actor_.selectRow(w->address, (int)j["row"].asNum((double)a1));
    else if (fn == "setText") {
        r = actor_.setText(w->address, j["value"].asStr());
        if (!r.ok && r.error.find("export bulunamadi") != std::string::npos) {
            // V3.2 — statik Qt: QLineEdit::setText SLOT'tur — qt_static_metacall yolu
            std::string val = j["value"].asStr();
            r = actor_.callSlot(w->address, "setText", j["timeout"].asNum(5000), &val);
        }
    }
    else {
        // dogrudan sinif::metot cagrisi: {"fn":"MyClass::mySlot"}
        auto pos = fn.find("::");
        if (pos == std::string::npos) return { false, "fn 'Class::method' biciminde olmali" };
        std::string cls = fn.substr(0, pos), meth = fn.substr(pos + 2);
        r = actor_.invokeMethod(w->address, cls, meth, a1);
        if (!r.ok && r.error.find("export bulunamadi") != std::string::npos) {
            // V3.2 — statik Qt hedef: qt_static_metacall ile slot'u tetikle
            // (VMProtect gibi export'suz Qt gömülü hedeflerde "butona bas" yolu)
            std::string val = j["value"].asStr();
            std::string* pval = (!val.empty() && j["value"].isStr()) ? &val : nullptr;
            r = actor_.callSlot(w->address, meth, j["timeout"].asNum(5000), pval);
        }
    }
    if (invoker_) invoker_->releaseThread();
    lastData_ = actionResult(fn, w->address, r);
    if (!r.ok && !r.pending) return { false, r.error };
    return { true, "" };
}

// =====================================================================
//  rescan / bekleme komutlari
// =====================================================================
std::pair<bool,std::string> Agent::cmdRescan(const Json& j) {
    (void)j;
    if (!analyzed_ || !analyzer_) return { false, "once attach+analyze" };
    if (invoker_) invoker_->pollPending();
    AnalyzeOptions opt;
    std::string diff = analyzer_->monitorStep(report_, opt);
    lastData_ = Json::mkObj();
    Json events = Json::mkArr();
    if (!diff.empty()) {
        std::istringstream ss(diff);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty()) events.push(line);
        }
    }
    lastData_.set("events", events);
    lastData_.set("forms", (double)report_.forms.size());
    lastData_.set("widgets", (double)report_.totalWidgets);
    lastData_.set("objects", (double)report_.totalQObjects);
    refreshFormWidgetCache();   // V3.2: rescan sonrasi formlar da tazele
    return { true, "" };
}

// =====================================================================
//  V3.3: NESNE ENVANTERI — "objects"
//  Tum QObject orneklerini (widget OLMAYANLAR dahil: Property, Model,
//  Manager siniflari...) sinif filtresiyle listeler. Her nesne icin:
//    - address, class, objectName
//    - "fields": nesne govdesindeki QString uye alanlari (ad/deger
//      metinleri — VMProtect'in BoolProperty("Memory Protection") gibi
//      ozellik nesneleri boyle okunur). SS/OCR YOK, saf bellek.
//  {"cmd":"objects","class":"Property","fields":true,"limit":400}
// =====================================================================
std::pair<bool,std::string> Agent::cmdObjects(const Json& j) {
    if (!analyzed_ || !analyzer_) return { false, "once attach+analyze" };
    std::string clsFilter = j["class"].asStr("");
    bool wantFields = j["fields"].asBool(true);
    int limit = (int)j["limit"].asNum(400);
    unsigned rawN = (unsigned)j["raw"].asNum(0);      // V3.3: ham bayt dökümü (0 = kapalı)

    // taze nesne taramasi (ayni yigin-pipline; ClassRegistry hazir)
    auto objs = analyzer_->scanInstances();
    IProcessReader& P = analyzer_->proc();
    QtLayouts& L = analyzer_->layouts();
    ClassRegistry& reg = analyzer_->registry();
    QtReader R(P, L);
    int PW = P.ptrSize();

    Json arr = Json::mkArr();
    int n = 0;
    for (Addr o : objs) {
        if (n >= limit) break;
        Addr vt = P.readAddr(o);
        if (!vt || vt < 0x1000) continue;
        const MetaClassInfo* ci = reg.resolveVtable(vt);
        if (!ci) continue;
        if (!clsFilter.empty() && ci->className.find(clsFilter) == std::string::npos)
            continue;

        Json e = Json::mkObj();
        e.set("address", jaddr(o));
        e.set("class", ci->className);

        // wasDeleted atla (d -> flags bitfield)
        Addr d = P.readAddr(o + PW);
        if (d && d > 0x1000) {
            uint32_t bits = P.readU32(d + L.flags_bits);
            if ((bits >> L.wasDeleted_bit) & 1) continue;
        }

        // objectName (ExtraData)
        std::string objName;
        if (d && d > 0x1000) {
            Addr ed = P.readAddr(d + L.extraData);
            if (ed && ed > 0x1000) {
                if (L.hasPlainObjectName && L.ed_objectName != 0xFFFFFFFFu) {
                    auto s = R.readQString(ed + L.ed_objectName);
                    if (s.valid) objName = s.utf8;
                } else {
                    for (unsigned off = 72; off < 160; off += 8) {
                        auto s = R.readQString(ed + off);
                        if (s.valid && !s.utf8.empty() && s.utf8.size() < 128) {
                            objName = s.utf8;
                            break;
                        }
                    }
                }
            }
        }
        e.set("objectName", objName);

        // V3.3: ham bayt dökümü — değer alanlarının ofset analizi icin
        if (rawN > 0 && rawN <= 0x400) {
            std::vector<uint8_t> buf(rawN);
            if (P.read(o, buf.data(), rawN)) {
                static const char* HX = "0123456789abcdef";
                std::string hx;
                hx.reserve(rawN * 2);
                for (uint8_t b : buf) { hx += HX[b >> 4]; hx += HX[b & 15]; }
                e.set("raw", hx);
            }
        }

        // QString uye alan taramasi: govde icinde QString d-isaretcileri
        if (wantFields) {
            Json fs = Json::mkArr();
            int fc = 0;
            for (unsigned off = 2 * (unsigned)PW; off < 0x1A0 && fc < 16; off += (unsigned)PW) {
                auto s = R.readQString(o + off);
                if (s.valid && !s.utf8.empty() && s.utf8.size() < 256) {
                    Json fj = Json::mkObj();
                    fj.set("off", (double)off);
                    fj.set("value", s.utf8);
                    fs.push(fj);
                    fc++;
                }
            }
            if (fc > 0) e.set("fields", fs);
        }
        arr.push(e);
        n++;
    }
    lastData_ = Json::mkObj();
    lastData_.set("count", (double)n);
    lastData_.set("objects", arr);
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdWaitForm(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    std::string title = j["title"].asStr();
    int timeout = (int)j["timeout"].asNum(8000);
    size_t initialForms = report_.forms.size();
    auto t0 = std::chrono::steady_clock::now();
    while (true) {
        if (invoker_) invoker_->pollPending();
        AnalyzeOptions opt;
        analyzer_->monitorStep(report_, opt);
        // (1) basligi eslesen form
        for (auto& f : report_.forms)
            if (!title.empty() && containsCI(f.windowTitle, title)) {
                lastData_ = formJson(f, true);
                return { true, "" };
            }
        // (2) baslik verilmediyse: YENI form (sayi artisi)
        if (title.empty() && report_.forms.size() > initialForms) {
            lastData_ = formJson(report_.forms.back(), true);
            return { true, "" };
        }
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (el * 1000 > timeout) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    return { false, "form zaman asimi: '" + title + "'" };
}

std::pair<bool,std::string> Agent::cmdWaitWidget(const Json& j) {
    if (!analyzed_) return { false, "once attach+analyze" };
    int timeout = (int)j["timeout"].asNum(8000);
    auto t0 = std::chrono::steady_clock::now();
    while (true) {
        if (invoker_) invoker_->pollPending();
        AnalyzeOptions opt;
        analyzer_->monitorStep(report_, opt);
        std::string err;
        Json probe = j;
        probe.set("rescan", false);   // ustte yeni tarama yaptik
        const WidgetInfo* w = findWidget(probe, &err);
        if (w) {
            lastData_ = widgetJson(*w, false);
            return { true, "" };
        }
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (el * 1000 > timeout) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    return { false, "widget zaman asimi" };
}

std::pair<bool,std::string> Agent::cmdSh(const Json& j) {
    if (!allowShell_) return { false, "sh komutu kapali — --allow-shell ile baslatin" };
    // dikuşik: protokol "cmd"=sh; shell string'i "run" (veya legacy "shell") alanında
    std::string c = j["run"].asStr();
    if (c.empty()) c = j["shell"].asStr();
    if (c.empty()) return { false, "run verilmeli" };
    if (invoker_) invoker_->releaseThread();
    FILE* p = popen(c.c_str(), "r");
    if (!p) return { false, "popen basarisiz" };
    std::string outp;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) outp.append(buf, n);
    int rc = pclose(p);
    lastData_ = Json::mkObj();
    lastData_.set("rc", (double)rc);
    lastData_.set("out", outp.substr(0, 4096));
    return { rc == 0, "" };
}

std::pair<bool,std::string> Agent::cmdScript(const Json& j) {
    std::string path = j["file"].asStr();
    if (path.empty()) return { false, "file verilmeli" };
    // icki script: ayni oturumda komut dizisini calistir
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return { false, "acilamadi: " + path };
    std::string text;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    fclose(f);
    Json arr;
    if (!JsonParser::parse(text, arr)) return { false, "script JSON'u bozuk" };
    Json results = Json::mkArr();
    if (arr.isObj()) { auto r = execute(arr); results.push(r); }
    else if (arr.isArr()) {
        for (auto& c : arr.arr) {
            Json r = execute(c);
            results.push(r);
            if (quit_) break;
        }
    }
    lastData_ = Json::mkObj();
    lastData_.set("results", results);
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdQuit(const Json& j) {
    (void)j;
    quit_ = true;
    lastData_ = Json::mkObj();
    lastData_.set("bye", true);
    return { true, "" };
}

// =====================================================================
//  V3.2 — X11 GİRİŞ KATMANI (wine hedefleri; Windows SendMessage dengi)
//  XTEST sentetik olaylarla klavye/fare — Qt bunları GERÇEK input işler.
//  KANIT: VMProtect 3.9.4 + F9 → Test_64_MemoryProtection.vmp.exe (6,6 MB).
// =====================================================================
static bool x11EnsureFocus(void* dpy, unsigned long* winOut = nullptr) {
    unsigned long win = X11Input::largestWindow(dpy);
    if (win) X11Input::focusWindow(dpy, win);
    if (winOut) *winOut = win;
    return true;
}

std::pair<bool,std::string> Agent::cmdXKey(const Json& j) {
    std::string spec = j["keysym"].asStr();       // "F9", "Ctrl+F9", "Ins", "a"
    if (spec.empty()) return { false, "keysym verilmeli (örn. F9 / Ctrl+F9)" };
    if (!X11Input::available())
        return { false, "X11 giriş yok (DISPLAY ayarlı mı? libX11/libXtst yüklü mü?)" };
    void* dpy = X11Input::open();
    if (!dpy) return { false, "X açılamadı" };

    // değiştiricileri ayır: "Ctrl+Shift+F9" → [Ctrl, Shift] + F9
    std::vector<std::string> parts;
    std::istringstream ss(spec);
    std::string seg;
    while (std::getline(ss, seg, '+')) parts.push_back(seg);
    std::string last = parts.back(); parts.pop_back();

    x11EnsureFocus(dpy);
    bool ok = true;
    std::vector<unsigned int> mods;
    for (auto& m : parts) {
        unsigned long ksm = X11Input::keysymFromName(m);
        if (m == "Ctrl" || m == "ctrl") ksm = 0xffe3;    // Control_L
        if (m == "Shift" || m == "shift") ksm = 0xffe1;  // Shift_L
        if (m == "Alt" || m == "alt") ksm = 0xffe9;      // Alt_L
        unsigned int kc = X11Input::keycodeForKeysym(dpy, ksm);
        if (kc) { mods.push_back(kc); X11Input::sendKeycode(dpy, kc, 1); }
    }
    unsigned long ks = X11Input::keysymFromName(last);
    unsigned int kc = X11Input::keycodeForKeysym(dpy, ks);
    if (!kc) { X11Input::close(dpy); return { false, "keysym çözülemedi: " + last }; }
    ok = X11Input::sendKeycode(dpy, kc, 3);   // press + release
    for (auto it = mods.rbegin(); it != mods.rend(); ++it)
        X11Input::sendKeycode(dpy, *it, 2);   // değiştiricileri bırak

    lastData_ = Json::mkObj();
    lastData_.set("keysym", spec);
    lastData_.set("keycode", (double)kc);
    lastData_.set("sent", ok);
    X11Input::close(dpy);
    return ok ? std::make_pair(true, std::string(""))
             : std::make_pair(false, std::string("tuş gönderilemedi"));
}

std::pair<bool,std::string> Agent::cmdXClick(const Json& j) {
    int x = (int)j["x"].asNum(-1), y = (int)j["y"].asNum(-1);
    unsigned int btn = (unsigned int)j["button"].asNum(1);
    if (x < 0 || y < 0) return { false, "x,y koordinatları verilmeli" };
    if (!X11Input::available())
        return { false, "X11 giriş yok (DISPLAY ayarlı mı? libX11/libXtst yüklü mü?)" };
    void* dpy = X11Input::open();
    if (!dpy) return { false, "X açılamadı" };
    x11EnsureFocus(dpy);
    bool ok = X11Input::clickAt(dpy, x, y, btn);
    lastData_ = Json::mkObj();
    lastData_.set("x", (double)x);
    lastData_.set("y", (double)y);
    lastData_.set("button", (double)btn);
    lastData_.set("clicked", ok);
    X11Input::close(dpy);
    return ok ? std::make_pair(true, std::string(""))
             : std::make_pair(false, std::string("tıklama gönderilemedi"));
}

std::pair<bool,std::string> Agent::cmdXType(const Json& j) {
    std::string text = j["text"].asStr();
    if (text.empty()) return { false, "text verilmeli" };
    if (!X11Input::available())
        return { false, "X11 giriş yok (DISPLAY ayarlı mı? libX11/libXtst yüklü mü?)" };
    void* dpy = X11Input::open();
    if (!dpy) return { false, "X açılamadı" };
    x11EnsureFocus(dpy);
    for (char c : text) {
        std::string s(1, c);
        unsigned long ks = X11Input::keysymFromName(s);
        unsigned int kc = X11Input::keycodeForKeysym(dpy, ks);
        if (kc) X11Input::sendKeycode(dpy, kc, 3);
    }
    lastData_ = Json::mkObj();
    lastData_.set("typed", text);
    X11Input::close(dpy);
    return { true, "" };
}

std::pair<bool,std::string> Agent::cmdXWindows(const Json& j) {
    (void)j;
    if (!X11Input::available())
        return { false, "X11 giriş yok (DISPLAY ayarlı mı? libX11/libXtst yüklü mü?)" };
    void* dpy = X11Input::open();
    if (!dpy) return { false, "X açılamadı" };
    unsigned long win = X11Input::largestWindow(dpy);
    lastData_ = Json::mkObj();
    lastData_.set("largest", jaddr(win));
    lastData_.set("display", getenv("DISPLAY") ? getenv("DISPLAY") : "");
    X11Input::close(dpy);
    return { true, "" };
}

} // namespace umvpqt
