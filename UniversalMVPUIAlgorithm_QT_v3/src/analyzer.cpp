// UMVPQT GOD STATE — Analyzer implementation
// ============================================================================
//  Butun GOD hatlari burada kosar. XPRO analyzer.h'in Qt karsiligi.
// ============================================================================
#include "umvpqt/analyzer.h"
#include <cstdio>
#include <cctype>
#include <algorithm>
#include <set>
#include <sys/stat.h>

namespace umvpqt {

static std::string hex(Addr a) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llx", (unsigned long long)a);
    return buf;
}
static std::string sanitizeFileName(std::string s) {
    for (auto& c : s) if (!isalnum((unsigned char)c) && c != '_' && c != '.') c = '_';
    return s;
}

Analyzer::Analyzer(std::unique_ptr<IProcessReader> proc) : proc_(std::move(proc)) {}

bool Analyzer::setupModules() { return mt_.load(*proc_); }

bool Analyzer::detectQt() {
    if (!QtDetector::detect(*proc_, mt_, L_, qt_)) return false;
    L_.resolve(qt_, *proc_);
    // QWidget staticMetaObject hizlandirma
    reg_.qwidgetStaticMetaObject = mt_.staticMetaObjectOf("QWidget");
    return true;
}

std::vector<Addr> Analyzer::scanInstances() {
    return InstanceScan::scanQObjects(*proc_, L_, mt_);
}

// ------------------------------------------------------------ widget ----
void Analyzer::fillWidget(WidgetInfo& w, const MetaClassInfo& ci, const AnalyzeOptions& opt) {
    IProcessReader& P = *proc_;
    int PW = P.ptrSize();
    Addr d = P.readAddr(w.address + PW);
    if (!d) return;

    // ---- geometry: QWidgetPrivate::data -> QWidgetData::crect ----
    if (L_.wp_data != 0xFFFFFFFFu) {
        Addr dataAddr = d + L_.wp_data;
        int32_t x1 = P.readI32(dataAddr + L_.wd_crect);
        int32_t y1 = P.readI32(dataAddr + L_.wd_crect + 4);
        int32_t x2 = P.readI32(dataAddr + L_.wd_crect + 8);
        int32_t y2 = P.readI32(dataAddr + L_.wd_crect + 12);
        if (x1 || y1 || x2 || y2) {
            w.x = x1; w.y = y1;
            w.w = x2 - x1 + 1; w.h = y2 - y1 + 1;
            if (w.w < 0 || w.w > 32000) w.w = 0;
            if (w.h < 0 || w.h > 32000) w.h = 0;
        }
        // ---- visible: widget_attributes & (1 << WA_Visible) ----
        uint32_t attrs = P.readU32(dataAddr + L_.wd_widget_attributes);
        w.visible = (attrs >> (L_.WA_Visible % 32)) & 1;
    }

    // ---- global konum: atalarin crect'lerini topla ----
    Addr par = P.readAddr(d + L_.parent);
    int gx = w.x, gy = w.y, guard = 0;
    while (par && guard++ < 16) {
        Addr pd = P.readAddr(par + PW);
        if (!pd) break;
        Addr pdata = pd + L_.wp_data;
        gx += P.readI32(pdata + L_.wd_crect);
        gy += P.readI32(pdata + L_.wd_crect + 4);
        Addr pp = P.readAddr(pd + L_.parent);
        if (pp == par) break;   // dongu guvenligi
        par = pp;
    }
    w.globalX = gx; w.globalY = gy;

    // ---- toolTip ----
    if (opt.textDecode && L_.wp_toolTip != 0xFFFFFFFFu) {
        auto s = QtReader(P, L_).readQString(d + L_.wp_toolTip);
        if (s.valid && !s.utf8.empty()) w.toolTip = s.utf8;
    }

    // ---- windowTitle (pencere olanlar: top-level VEYA Qt::Window bayrakli —
    //      QDialog gibi parent'li pencereler dahil) ----
    {
        bool isWindow = w.topLevel;
        if (!isWindow && L_.wp_data != 0xFFFFFFFFu && d) {
            uint32_t wflags = P.readU32(d + L_.wp_data + L_.wd_window_flags);
            isWindow = (wflags & 1) != 0;    // Qt::Window bit0 (Dialog=0x3, Tool=0xc...)
        }
        if (isWindow && L_.wp_extra != 0xFFFFFFFFu) {
            Addr extra = P.readAddr(d + L_.wp_extra);
            if (extra && extra > 0x1000) {
                Addr tle = P.readAddr(extra + L_.qwe_topextra);
                if (tle && tle > 0x1000 && L_.tle_caption != 0xFFFFFFFFu) {
                    auto s = QtReader(P, L_).readQString(tle + L_.tle_caption);
                    if (s.valid) w.windowTitle = s.utf8;
                }
            }
        }
    }

    // ---- objectName ----
    if (opt.textDecode) {
        Addr ed = P.readAddr(d + L_.extraData);
        if (ed && ed > 0x1000) {
            if (L_.hasPlainObjectName && L_.ed_objectName != 0xFFFFFFFFu) {
                auto s = QtReader(P, L_).readQString(ed + L_.ed_objectName);
                if (s.valid) w.objectName = s.utf8;
            } else {
                // Qt6: compat-property saklamasi — ExtraData icinde QString oruntusu tara
                QtReader R(P, L_);
                for (unsigned off = 72; off < 160; off += 8) {
                    auto s = R.readQString(ed + off);
                    if (s.valid && !s.utf8.empty() && s.utf8.size() < 128) {
                        bool identik = true;
                        for (char c : s.utf8)
                            if (!(isalnum((unsigned char)c) || c == '_' || c == ' ')) { identik = false; break; }
                        if (identik) { w.objectName = s.utf8; break; }
                    }
                }
            }
        }
    }

    // ---- tipine gore metin ----
    if (opt.textDecode) {
        QtReader R(P, L_);
        auto chainHas = [&](const char* cls) {
            if (ci.className == cls) return true;
            for (auto& s : ci.superChain) if (s == cls) return true;
            return false;
        };
        if (chainHas("QAbstractButton") && L_.ab_text != 0xFFFFFFFFu) {
            auto s = R.readQString(d + L_.ab_text);
            if (s.valid) w.text = s.utf8;
        } else if (chainHas("QLabel") && L_.lb_text != 0xFFFFFFFFu) {
            auto s = R.readQString(d + L_.lb_text);
            if (s.valid) w.text = s.utf8;
        } else if (chainHas("QLineEdit") && L_.le_control != 0xFFFFFFFFu) {
            Addr ctrl = P.readAddr(d + L_.le_control);
            if (ctrl > 0x1000 && L_.wlc_m_text != 0xFFFFFFFFu) {
                auto s = R.readQString(ctrl + L_.wlc_m_text);
                if (s.valid) w.editText = s.utf8;
            }
        }
    }
}

WidgetInfo Analyzer::makeWidget(Addr obj, const MetaClassInfo* ci, const AnalyzeOptions& opt, int depth) {
    IProcessReader& P = *proc_;
    WidgetInfo w;
    w.address = obj;
    w.vtable = P.readAddr(obj);
    int PW = P.ptrSize();
    Addr d = P.readAddr(obj + PW);
    if (ci) {
        w.className = ci->classNameResolved.empty() ? ci->className : ci->classNameResolved;
    }
    // parent / cocuklar
    if (d) {
        w.parent = P.readAddr(d + L_.parent);
        auto kids = QtReader(P, L_).readListAddrs(d + L_.children, 512);
        w.children = kids;
        // top-level: parentsiz widget
        w.topLevel = (w.parent == 0);
        if (w.parent && w.parent < 0x1000) w.topLevel = true;
    }
    fillWidget(w, ci ? *ci : MetaClassInfo{}, opt);
    (void)depth;
    return w;
}

// -------------------------------------------------- agac + ozellikler ----
void Analyzer::buildTreeAndProperties(AnalysisReport& rpt, const std::vector<Addr>& objs,
                                      const AnalyzeOptions& opt) {
    std::vector<WidgetInfo> widgets;
    std::set<Addr> widgetAddrs;
    for (Addr o : objs) {
        Addr vt = proc_->readAddr(o);
        const MetaClassInfo* ci = reg_.resolveVtable(vt);
        if (!ci) continue;
        if (!reg_.isWidgetClass(*ci)) continue;
        // silinmis nesne atla
        int PW = proc_->ptrSize();
        Addr d = proc_->readAddr(o + PW);
        uint32_t bits = proc_->readU32(d + L_.flags_bits);
        if ((bits >> L_.wasDeleted_bit) & 1) continue;

        WidgetInfo w = makeWidget(o, ci, opt, 0);
        widgets.push_back(std::move(w));
        widgetAddrs.insert(o);
    }
    rpt.totalWidgets = (int)widgets.size();
    rpt.totalQObjects = (int)objs.size();

    // ---- formlar: top-level widget'ler + Qt::Window bayrakli pencereler ----
    // (QDialog/Dock gibi parent'LI ama pencere olan widget'lar da formdur —
    //  window_flags bit0 = Qt::Window: Dialog=0x3, Window=0x1, Tool=0xc...)
    for (auto& w : widgets) {
        if (!w.topLevel) {
            int PW2 = proc_->ptrSize();
            Addr d2 = proc_->readAddr(w.address + PW2);
            uint32_t wflags = d2 ? proc_->readU32(d2 + L_.wp_data + L_.wd_window_flags) : 0;
            if (!(wflags & 1)) continue;   // gomulu cocuk widget — form degil
        }
        FormInfo f;
        f.address = w.address;
        f.className = w.className;
        f.objectName = w.objectName;
        f.windowTitle = w.windowTitle;
        f.visible = w.visible;
        f.x = w.x; f.y = w.y; f.w = w.w; f.h = w.h;
        // cocuklari rekursif topla (derinlik sinirli)
        std::vector<std::pair<Addr, int>> frontier;
        for (Addr c : w.children) frontier.push_back({ c, 1 });
        int guardCount = 0;
        while (!frontier.empty() && guardCount < 2048) {
            auto [c, dep] = frontier.back();
            frontier.pop_back();
            guardCount++;
            if (c < 0x1000) continue;
            if (!widgetAddrs.count(c)) {
                continue;   // widget listesinde yok (silinmis/Qt ic) — yine de cocuk listesine ekle
            }
            Addr vt = proc_->readAddr(c);
            const MetaClassInfo* cci = reg_.resolveVtable(vt);
            WidgetInfo cw = makeWidget(c, cci, opt, dep);
            // ONCE cocuklari topla (push_back(std::move) cw'yi bosaltr!)
            if (dep < 8) {
                for (Addr gc : cw.children) if (gc > 0x1000) frontier.push_back({ gc, dep + 1 });
            }
            f.widgets.push_back(std::move(cw));
        }
        f.widgetCount = (int)f.widgets.size();
        rpt.forms.push_back(std::move(f));
    }
    // sinif listesi rapor'a
    for (auto& [vt, ci] : reg_.byVtable) rpt.classes.push_back(ci);
    for (auto& [mo, ci] : reg_.byMetaObject) rpt.classes.push_back(ci);
}

// ------------------------------------------------------- event analizi --
void Analyzer::extractEvents(AnalysisReport& rpt, const AnalyzeOptions& opt) {
    (void)opt;
    ConnectionWalker walker(*proc_, L_, reg_);
    // formlardaki widget'larin giden baglantilari
    for (auto& f : rpt.forms) {
        for (auto& w : f.widgets) {
            auto cs = walker.outgoing(w.address);
            for (auto& c : cs) {
                rpt.allConnections.push_back(c);
                w.connections.push_back(c);
                if (c.signalName == "clicked" || c.signalName == "pressed" ||
                    c.signalName == "toggled" || c.signalName == "triggered") {
                    w.hasClickHandler = true;
                    if (w.clickHandlerName.empty()) w.clickHandlerName = c.slotSignature;
                }
                // handler kod adresi: PMF'den (slotCode) veya receiver metacall cozumunden
                {
                    Addr handlerAddr = 0;
                    if (c.slotCode) handlerAddr = c.slotCode;
                    else if (c.callFunction) {
                        Addr rvt = proc_->readAddr(c.receiver);
                        if (const MetaClassInfo* rci = reg_.resolveVtable(rvt)) {
                            auto it = rci->methodCode.find(c.slotMethodIndex);
                            if (it != rci->methodCode.end()) handlerAddr = it->second;
                        }
                    }
                    if (!c.slotSignature.empty() && handlerAddr) {
                        WidgetInfo::Handler h;
                        h.kind = "slot";
                        h.name = c.slotSignature;
                        h.start = handlerAddr;
                        Addr end = 0;
                        dis_.functionExtent(h.start, end);
                        h.end = end;
                        const Module* m = mt_.moduleOf(h.start);
                        h.module = m ? m->name : "?";
                        w.handlers.push_back(h);
                    }
                }
            }
        }
        // form'un kendi baglantilari
        auto cs = walker.outgoing(f.address);
        for (auto& c : cs) rpt.allConnections.push_back(c);
    }
}

void Analyzer::extractClassHandlers(AnalysisReport& rpt, const AnalyzeOptions& opt) {
    if (!opt.code) return;
    // metacall cozumlemesi (sinif basina 1 kez)
    for (auto& [vt, ci] : reg_.byVtable) {
        if (!ci.staticMetacall) continue;
        auto mc = dis_.parseMetacall(ci.staticMetacall, (int)ci.methods.size());
        ci.methodCode = mc;
    }
    // vtable override tespiti: paintEvent/mousePressEvent...
    if (!vslots_.proc) vslots_.build(*proc_, mt_, "QWidget");
    for (auto& f : rpt.forms) {
        for (auto& w : f.widgets) {
            for (auto& [name, slot] : vslots_.slots) {
                Addr o = vslots_.overridden(w.vtable, name);
                if (o) {
                    WidgetInfo::Handler h;
                    h.kind = "override";
                    h.name = name;
                    h.start = o;
                    Addr end = 0;
                    dis_.functionExtent(o, end);
                    h.end = end;
                    const Module* m = mt_.moduleOf(o);
                    h.module = m ? m->name : "?";
                    w.handlers.push_back(h);
                }
            }
        }
    }
    // .asm dump
    if (!opt.asmDir.empty()) {
        mkdir(opt.asmDir.c_str(), 0755);
        for (auto& f : rpt.forms) {
            for (auto& w : f.widgets) {
                for (auto& h : w.handlers) {
                    if (!h.start || !h.end) continue;
                    std::string fn = opt.asmDir + "/" + sanitizeFileName(w.className + "_" + h.name + "_" + hex(h.start)) + ".asm";
                    std::string txt = dis_.disasmText(h.start, h.end);
                    if (!txt.empty()) {
                        FILE* fp = fopen(fn.c_str(), "w");
                        if (fp) {
                            fprintf(fp, "; UMVPQT GOD asm dump\n; class: %s\n; handler: %s\n; range: 0x%llx - 0x%llx\n",
                                    w.className.c_str(), h.name.c_str(),
                                    (unsigned long long)h.start, (unsigned long long)h.end);
                            fwrite(txt.data(), 1, txt.size(), fp);
                            fclose(fp);
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- run ----
AnalysisReport Analyzer::run(const AnalyzeOptions& opt) {
    AnalysisReport rpt;
    rpt.pid = proc_->pid();
    rpt.processName = proc_->name();
    try {
        if (!setupModules()) return rpt;
        if (!detectQt()) { rpt.qt.present = false; return rpt; }
        rpt.qt = qt_;
    } catch (const std::exception& e) {
        fprintf(stderr, "[!] kurulum hatasi: %s\n", e.what());
        return rpt;
    }
    try {
        // parser + registry kur
        moParser_ = std::make_unique<MetaObjectParser>(*proc_, L_, mt_);
        reg_.proc = &*proc_;
        reg_.L = &L_;
        reg_.mt = &mt_;
        reg_.moParser = &*moParser_;
        dis_.init(*proc_, mt_);

        if (!opt.live) {
            // sadece kod analizi: metaobject taramasi yapilmadan sinif cikarimi sinirli
            return rpt;
        }
        auto objs = scanInstances();
        buildTreeAndProperties(rpt, objs, opt);
        extractClassHandlers(rpt, opt);
        extractEvents(rpt, opt);
    } catch (const std::exception& e) {
        fprintf(stderr, "[!] analiz hatasi: %s\n", e.what());
        return rpt;
    }

    // combobox degerleri
    if (opt.textDecode) {
        QtReader R(*proc_, L_);
        ComboModelReader combo(*proc_, L_, reg_, R);
        for (auto& f : rpt.forms) {
            for (auto& w : f.widgets) {
                // QComboBox mi? (sinif zincirinde)
                bool isCombo = w.className.find("QComboBox") != std::string::npos;
                if (!isCombo) {
                    Addr vt = w.vtable;
                    if (const MetaClassInfo* ci = reg_.resolveVtable(vt))
                        isCombo = reg_.chainContains(*ci, "QComboBox");
                }
                if (isCombo) {
                    combo.readCombo(w.address, w.comboItems, w.comboCurrentIndex, w.comboCurrentText);
                    if (w.text.empty()) w.text = w.comboCurrentText;
                }
            }
        }
    }
    return rpt;
}

// ------------------------------------------------------------ monitor ----
std::string Analyzer::monitorStep(AnalysisReport& prev, const AnalyzeOptions& opt) {
    AnalysisReport now = run(opt);
    std::string out;
    // yeni form?
    for (auto& f : now.forms) {
        bool seen = false;
        for (auto& p : prev.forms) if (p.address == f.address) { seen = true; break; }
        if (!seen)
            out += "[YENI FORM] " + (f.windowTitle.empty() ? f.className : f.windowTitle) +
                   " (0x" + hex(f.address) + ")\n";
    }
    // kaybolan form
    for (auto& p : prev.forms) {
        bool seen = false;
        for (auto& f : now.forms) if (p.address == f.address) { seen = true; break; }
        if (!seen) out += "[KAPANAN FORM] " + (p.windowTitle.empty() ? p.className : p.windowTitle) + "\n";
    }
    // yeni widget (adres bazli)
    for (auto& f : now.forms) {
        FormInfo* pf = nullptr;
        for (auto& p : prev.forms) if (p.address == f.address) { pf = &p; break; }
        if (!pf) continue;
        for (auto& w : f.widgets) {
            bool seen = false;
            for (auto& pw : pf->widgets) if (pw.address == w.address) { seen = true; break; }
            if (!seen)
                out += "[YENI WIDGET] " + w.className + " text='" + w.text +
                       (w.objectName.empty() ? "" : "' name=" + w.objectName) +
                       " @0x" + hex(w.address) + "\n";
        }
        // metin degisimi
        for (auto& w : f.widgets) {
            for (auto& pw : pf->widgets) {
                if (pw.address != w.address) continue;
                if (pw.text != w.text && !w.text.empty())
                    out += "[METIN DEGISIMI] " + w.className + " '" + pw.text + "' -> '" + w.text + "'\n";
                if (pw.comboCurrentText != w.comboCurrentText && !w.comboCurrentText.empty())
                    out += "[COMBO SECIMI] " + w.className + " -> '" + w.comboCurrentText + "'\n";
                if (pw.visible != w.visible)
                    out += "[GORUNURLUK] " + w.className + (w.visible ? " acildi" : " kapandi") + "\n";
            }
        }
    }
    prev = std::move(now);
    return out;
}

} // namespace umvpqt
