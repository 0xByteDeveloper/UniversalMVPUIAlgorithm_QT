// =============================================================================
// UMVP-QT // src/analyzer.cpp — orchestration.
// =============================================================================
#include "umvpqt/analyzer.h"
#include "umvpqt/disasm.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <queue>

namespace umvpqt {

QtVersion Analyzer::detectQtVersion() {
    QtVersion v;
    // 1) module hint
    for (const ModuleInfo& m : r_.modules()) {
        std::string n = m.name;
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        if (n.find("qt6core") != std::string::npos) {
            v.family = QtFamily::Qt6; v.module = m.name; break;
        }
        if (n.find("qt5core") != std::string::npos || n.find("qtcore") != std::string::npos) {
            v.family = QtFamily::Qt5; v.module = m.name; break;
        }
    }
    // 2) revision probe via first valid metaobject using candidate layouts
    if (v.family == QtFamily::Unknown) {
        for (QtFamily fam : {QtFamily::Qt5, QtFamily::Qt6}) {
            const QtLayout* L = layout_for(fam);
            ObjectScanner scanner(r_, *L);
            auto objs = scanner.scanObjects(32);
            if (!objs.empty()) {
                v.family = fam;
                // revision from the first metaobject
                MetaObjectReader mr(r_, *L);
                int rev, cls, mc, md, pc, pd, sc;
                if (mr.parseHeader(objs[0].metaObject, &rev, &cls, &mc, &md, &pc, &pd, &sc))
                    v.revision = rev;
                break;
            }
        }
    }
    // 3) V307-3 yaması — STATİK-Qt bellek imza fallback'i:
    //    modül yok + metaobject taraması da sonuç vermediyse (VMProtect gibi
    //    statik bağlanmış self-protected ikili dosyalar) bellekte Qt imzaları
    //    aranır. UTF-8 "qt_meta_stringdata"/"QMainWindow" + UTF-16 menü metinleri
    //    ("File"/"Edit"/"View") birlikte bulunursa → Qt5 (VMP ailesi Qt5'tir;
    //    "last resort Qt6" yanlış layout seçtirirdi).
    if (v.family == QtFamily::Unknown) {
        int u8 = 0, u16 = 0;
        static const char* kUtf8[]  = { "qt_meta_stringdata", "QMainWindow" };
        static const char* kUtf16[] = { "File", "Edit", "View" };
        for (const MemoryRegion& r : r_.regions()) {
            if (!(r.perms & 1u)) continue;          // okunabilir değil
            if (r.perms & 4u) continue;             // data/rodata/heap yeter
            Address sz = r.end - r.start;
            if (sz > 64ull * 1024 * 1024) continue; // hız sınırı
            std::vector<char> buf((size_t)sz);
            if (!r_.read(r.start, buf.data(), buf.size())) continue;
            for (const char* s : kUtf8)
                for (size_t i = 0; i + strlen(s) <= buf.size(); i++)
                    if (memcmp(buf.data() + i, s, strlen(s)) == 0) { u8++; break; }
            for (const char* s : kUtf16) {
                std::string w;
                for (const char* p = s; *p; p++) { w.push_back(*p); w.push_back('\0'); }
                for (size_t i = 0; i + w.size() <= buf.size(); i++)
                    if (memcmp(buf.data() + i, w.data(), w.size()) == 0) { u16++; break; }
            }
        }
        if (u8 > 0 && u16 > 0) {
            v.family = QtFamily::Qt5;
            v.module = "(memory-signature: Qt5 static)";
        }
    }
    if (v.family == QtFamily::Qt5) { v.major = 5; v.minor = 15; }
    else if (v.family == QtFamily::Qt6) { v.major = 6; v.minor = 8; }
    return v;
}

WidgetInfo Analyzer::buildWidgetInfo(const DiscoveredObject& o, int depth) {
    WidgetInfo w;
    w.object = o.object;
    w.vtable = o.vtable;
    w.className = o.className;
    w.classChain = o.classChain;
    w.objectName = o.objectName;
    w.isWidget = o.isWidget;
    w.isWindow = o.isWindow;
    w.rect = o.rect;
    w.hasRect = o.hasWidgetData;
    w.winId = o.winId;
    w.windowFlags = o.windowFlags;
    w.visible = o.inShow;
    w.text = o.text;
    w.textConfidence = o.textConfidence;
    w.comboItems = o.comboItems;
    w.comboCurrentIndex = o.comboCurrentIndex;
    w.comboCurrentText = o.comboCurrentText;
    w.comboConfidence = o.comboConfidence;
    w.metaObject = o.metaObject;
    w.depth = depth;
    w.parentObject = o.parent;
    w.overriddenVirtuals = o.overriddenVirtuals;
    return w;
}

AnalysisReport Analyzer::analyze(const AnalyzerOptions& opt) {
    AnalysisReport rep;
    rep.process = r_.info();

    QtVersion v = opt.familyOverride != QtFamily::Unknown
                      ? QtVersion{opt.familyOverride, -1, 0, 0, 0, "(override)"}
                      : detectQtVersion();
    if (v.family == QtFamily::Unknown) v.family = QtFamily::Qt6;   // last resort
    rep.qt = v;

    const QtLayout* L = layout_for(v.family);
    MetaObjectReader mr(r_, *L);
    ObjectScanner scanner(r_, *L);
    ConnectionScanner connections(r_, *L);

    // ---- sweep ----
    auto objects = scanner.scanObjects(opt.maxObjects);
    if (v.revision < 0 && !objects.empty()) {
        MetaObjectReader mrProbe(r_, *L);
        int rev, cls, mc, md, pc, pd, sc;
        if (mrProbe.parseHeader(objects[0].metaObject, &rev, &cls, &mc, &md, &pc, &pd, &sc))
            v.revision = rev;
        rep.qt = v;
    }
    rep.verifiedQObjects = (int)objects.size();
    rep.objectCount = (int)objects.size();

    // ---- index ----
    std::map<Address, DiscoveredObject> byAddr;
    for (auto& o : objects) byAddr[o.object] = o;

    // ---- vtable overrides ----
    for (auto& o : objects)
        o.overriddenVirtuals = scanner.detectVtableOverrides(objects, o);

    // ---- connections + handlers ----
    std::vector<WidgetInfo> widgets;
    widgets.reserve(objects.size());
    std::map<Address, WidgetInfo*> wByAddr;
    for (auto& o : objects) {
        WidgetInfo w = buildWidgetInfo(o, 0);
        widgets.push_back(w);
    }
    for (auto& w : widgets) wByAddr[w.object] = &w;

    int totalConns = 0, totalHandlers = 0;
    for (auto& w : widgets) {
        auto it = byAddr.find(w.object);
        if (it == byAddr.end()) continue;
        auto conns = connections.outgoing(it->second);
        totalConns += (int)conns.size();
        for (auto& ci : conns) {
            if (ci.sender == w.object) w.outgoingConnections.push_back(ci);
            else if (ci.receiver == w.object) w.incomingConnections.push_back(ci);
            if (ci.receiver == w.object) w.incomingConnections.push_back(ci);
        }
        for (auto& ci : w.outgoingConnections) {
            // resolve handler
            std::optional<HandlerInfo> h;
            if (ci.isSlotObject && ci.slotObject) {
                Address fn = r_.readPtr(ci.slotObject + 16);
                if (fn && r_.isExecutable(fn)) {
                    HandlerInfo hi;
                    hi.ownerClass = ci.slotOwnerClass.empty() ? "?" : ci.slotOwnerClass;
                    hi.methodName = ci.slotName.empty() ? "<functor>" : ci.slotName;
                    hi.entry = fn;
                    hi.base = fn;
                    hi.end = function_end(r_, fn);
                    hi.via = ci.slotObject;
                    hi.viaKind = "slot-object";
                    hi.confidence = 95;
                    hi.disasm = disassemble_range(r_, hi.base, hi.end);
                    h = hi;
                }
            } else if (opt.code && ci.callFunction && r_.isExecutable(ci.callFunction)) {
                MetacallSolve sol = solve_metacall(r_, ci.callFunction);
                for (const MetacallCase& mc : sol.cases) {
                    // local index of the slot within the RECEIVER class
                    int receiverOffset = 0;
                    auto rit = byAddr.find(ci.receiver);
                    if (rit != byAddr.end())
                        receiverOffset = mr.methodOffset(rit->second.metaObject);
                    int want = ci.slotMethodIndex - receiverOffset;
                    if (mc.localIndex != want || !mc.handler) continue;
                    HandlerInfo hi;
                    hi.ownerClass = ci.slotOwnerClass.empty() ? "?" : ci.slotOwnerClass;
                    hi.methodName = ci.slotName.empty()
                                        ? ("slot#" + std::to_string(ci.slotMethodIndex))
                                        : ci.slotName;
                    hi.entry = mc.handler;
                    hi.base = mc.handler;
                    hi.end = mc.handler == mc.caseTarget
                                 ? std::min(mc.caseTarget + 64, function_end(r_, mc.handler))
                                 : function_end(r_, mc.handler);
                    hi.via = ci.callFunction;
                    hi.viaKind = mc.handler == mc.caseTarget
                                     ? "qt_static_metacall-inlined" : "qt_static_metacall";
                    hi.confidence = mc.handler == mc.caseTarget ? 80 : 90;
                    hi.disasm = disassemble_range(r_, hi.base, hi.end);
                    h = hi;
                }
            }
            if (h) {
                totalHandlers++;
                w.handlers.push_back(*h);
                ci.slotFunction = h->entry;
            }
        }
        w.hasEventHandlers = !w.outgoingConnections.empty() || !w.handlers.empty() ||
                             !w.overriddenVirtuals.empty();
        // meta properties
        w.metaProperties = mr.allProperties(w.metaObject);
        w.staticMetacall = r_.readPtr(w.metaObject + L->mo_static_metacall);
    }

    // ---- invoke-mode enrichment (executor present) ----
    if (opt.invoke && ex_) {
        InvokeEngine inv(r_, *L, ex_);
        for (auto& w : widgets) {
            if (w.className == "QComboBox") {
                auto idx = inv.readProperty(byAddr[w.object], "currentIndex");
                auto txt = inv.readProperty(byAddr[w.object], "currentText");
                if (idx) { w.comboCurrentIndex = (int)idx->asInt; w.comboConfidence = 100; }
                if (txt) { w.comboCurrentText = txt->asString; w.comboConfidence = 100; }
                w.comboItems = inv.comboItems(byAddr[w.object]);
                if (!w.comboItems.empty()) w.comboConfidence = 100;
            }
            if (w.text.empty()) {
                auto t = inv.readProperty(byAddr[w.object], "text");
                if (t && !t->asString.empty()) {
                    w.text = t->asString;
                    w.textConfidence = 100;
                }
            }
        }
    }

    // ---- forms ----
    std::map<Address, int> widgetIndexOf;
    for (size_t i = 0; i < widgets.size(); ++i) widgetIndexOf[widgets[i].object] = (int)i;

    std::vector<int> formIdx;
    for (size_t i = 0; i < widgets.size(); ++i) {
        const auto& w = widgets[i];
        bool isWidgetClass = std::find(w.classChain.begin(), w.classChain.end(),
                                       "QWidget") != w.classChain.end();
        if (w.isWidget && isWidgetClass && w.parentObject == 0) formIdx.push_back((int)i);
    }
    // depth + subtree
    std::vector<int> depthOf(widgets.size(), -1);
    auto computeDepths = [&](int startIdx) {
        std::queue<std::pair<int, int>> q;
        q.push({startIdx, 0});
        while (!q.empty()) {
            auto [idx, d] = q.front();
            q.pop();
            if (depthOf[idx] >= 0) continue;
            depthOf[idx] = d;
            auto it = byAddr.find(widgets[idx].object);
            if (it == byAddr.end()) continue;
            for (Address child : it->second.children) {
                auto cit = widgetIndexOf.find(child);
                if (cit != widgetIndexOf.end() && depthOf[cit->second] < 0)
                    q.push({cit->second, d + 1});
            }
        }
    };

    int bestActive = -1;
    long long bestArea = -1;
    for (int fi : formIdx) {
        FormInfo f;
        const WidgetInfo& w = widgets[(size_t)fi];
        f.className = w.className;
        f.objectName = w.objectName;
        f.object = w.object;
        f.rect = w.rect;
        f.winId = w.winId;
        f.visible = w.visible;
        computeDepths(fi);
        // collect subtree
        std::queue<Address> q;
        auto rootIt = byAddr.find(w.object);
        if (rootIt != byAddr.end())
            for (Address c : rootIt->second.children) q.push(c);
        while (!q.empty()) {
            Address cur = q.front();
            q.pop();
            f.allChildren.push_back(cur);
            auto cit = widgetIndexOf.find(cur);
            if (cit != widgetIndexOf.end()) {
                f.widgets.push_back(widgets[(size_t)cit->second]);
                widgets[(size_t)cit->second].depth = depthOf[cit->second];
            }
            auto oit = byAddr.find(cur);
            if (oit != byAddr.end())
                for (Address c : oit->second.children) q.push(c);
        }
        f.widgetCount = (int)f.widgets.size();
        rep.forms.push_back(f);
        long long area = (long long)w.rect.w * w.rect.h;
        if (w.visible && (bestActive < 0 || area > bestArea)) {
            bestActive = (int)rep.forms.size() - 1;
            bestArea = area;
        }
    }
    rep.activeForm = bestActive;
    if (bestActive >= 0) rep.forms[(size_t)bestActive].isActive = true;

    // sync depths + finalize
    for (auto& f : rep.forms)
        for (auto& w : f.widgets) {
            auto it = widgetIndexOf.find(w.object);
            if (it != widgetIndexOf.end()) w = widgets[(size_t)it->second];
        }

    rep.allObjects = widgets;
    rep.connectionCount = totalConns;
    rep.handlerCount = totalHandlers;
    return rep;
}

} // namespace umvpqt
