// UMVPQT GOD STATE — Report implementation
// ============================================================================
#include "umvpqt/report.h"
#include <cstdio>
#include <cctype>
#include <sstream>

namespace umvpqt {

static std::string jstr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
        else o += c;
    }
    return o + "\"";
}
static std::string hx(Addr a) { char b[32]; snprintf(b, sizeof(b), "0x%llx", (unsigned long long)a); return b; }

std::string Report::summary(const AnalysisReport& r) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "QT %s | surum %s | QObject:%d | Widget:%d | Form:%d | Sinif:%d | Baglanti:%d",
             r.qt.era == QtEra::Qt6 ? "6" : r.qt.era == QtEra::Qt5 ? "5" : "4",
             r.qt.version.c_str(), r.totalQObjects, r.totalWidgets,
             (int)r.forms.size(), (int)r.classes.size(), (int)r.allConnections.size());
    return buf;
}

std::string Report::textTree(const AnalysisReport& r) {
    std::ostringstream o;
    o << "================ UMVPQT GOD STATE REPORT ================\n";
    o << "PID: " << r.pid << " (" << r.processName << ")\n";
    o << "Qt: " << (r.qt.era == QtEra::Qt6 ? "Qt6" : r.qt.era == QtEra::Qt5 ? "Qt5" : "Qt4")
      << "  surum: " << (r.qt.version.empty() ? "?" : r.qt.version)
      << "  [" << r.qt.detection << "]\n";
    o << "Toplam QObject: " << r.totalQObjects << " | Widget: " << r.totalWidgets
      << " | Form: " << r.forms.size() << "\n";
    o << "=========================================================\n\n";
    for (auto& f : r.forms) {
        o << "FORM: " << (f.windowTitle.empty() ? f.className : f.windowTitle)
          << "  [class=" << f.className << (f.objectName.empty() ? "" : " name=" + f.objectName) << "]\n";
        o << "  adres=" << hx(f.address) << "  pos=" << f.x << "," << f.y
          << "  size=" << f.w << "x" << f.h << "  visible=" << (f.visible ? "EVET" : "HAYIR") << "\n";
        o << "  widget sayisi: " << f.widgetCount << "\n";
        for (auto& w : f.widgets) {
            o << "    + " << w.className;
            if (!w.objectName.empty()) o << " [name=" << w.objectName << "]";
            if (!w.text.empty()) o << " text='" << w.text << "'";
            if (!w.editText.empty()) o << " edit='" << w.editText << "'";
            o << "  pos=" << w.x << "," << w.y << " size=" << w.w << "x" << w.h
              << (w.visible ? "" : " [GIZLI]");
            o << "  @" << hx(w.address) << "\n";
            if (!w.comboItems.empty()) {
                o << "      COMBO (" << w.comboItems.size() << "): ";
                for (size_t i = 0; i < w.comboItems.size() && i < 20; i++) {
                    o << (i == (size_t)w.comboCurrentIndex ? ">*" : "  ") << w.comboItems[i] << " ";
                }
                o << "\n      SECILI: " << w.comboCurrentText
                  << " (index " << w.comboCurrentIndex << ")\n";
            }
            // event durumu — yalniz kontrol widget'larinda anlamlidir
            bool isControl = w.className.find("Button") != std::string::npos ||
                             w.className.find("CheckBox") != std::string::npos ||
                             w.className.find("Radio") != std::string::npos ||
                             w.className.find("ComboBox") != std::string::npos ||
                             w.className.find("LineEdit") != std::string::npos ||
                             !w.connections.empty();
            if (isControl) {
                o << "      EVENT: " << (w.hasClickHandler ? "VAR" : "YOK (bos buton)");
                if (w.hasClickHandler && !w.clickHandlerName.empty()) o << " -> " << w.clickHandlerName;
                o << "\n";
            }
            for (auto& c : w.connections) {
                if (c.signalName.empty() && c.slotSignature.empty()) continue;
                o << "      CONNECT " << c.signalSignature << " -> " << c.slotSignature
                  << " [" << c.connectionType << "] @" << hx(c.connection) << "\n";
            }
            for (auto& h : w.handlers) {
                o << "      HANDLER(" << h.kind << ") " << h.name
                  << "  [" << hx(h.start) << " .. " << hx(h.end) << "] " << h.module << "\n";
            }
        }
        o << "\n";
    }
    // sinif envanteri
    o << "--- SINIF ENVANTERI (" << r.classes.size() << ") ---\n";
    for (auto& c : r.classes) {
        if (c.className.empty()) continue;
        o << "  " << c.className << "  metaObject=" << hx(c.metaObject)
          << "  metacall=" << hx(c.staticMetacall)
          << "  metod=" << c.methods.size() << " property=" << c.properties.size();
        if (!c.superChain.empty()) {
            o << "  zincir: ";
            for (size_t i = 0; i < c.superChain.size() && i < 6; i++) o << c.superChain[i] << " <- ";
        }
        o << "\n";
    }
    return o.str();
}

std::string Report::json(const AnalysisReport& r) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"pid\": " << r.pid << ", \"process\": " << jstr(r.processName) << ",\n";
    o << "  \"qt\": { \"present\": " << (r.qt.present ? "true" : "false")
      << ", \"era\": " << (int)r.qt.era << ", \"version\": " << jstr(r.qt.version)
      << ", \"revision\": " << r.qt.moRevision << " },\n";
    o << "  \"totals\": { \"qobjects\": " << r.totalQObjects << ", \"widgets\": " << r.totalWidgets
      << ", \"forms\": " << r.forms.size() << ", \"classes\": " << r.classes.size()
      << ", \"connections\": " << r.allConnections.size() << " },\n";
    o << "  \"forms\": [\n";
    bool firstForm = true;
    for (auto& f : r.forms) {
        if (!firstForm) o << ",\n";
        firstForm = false;
        o << "    { \"address\": \"" << hx(f.address) << "\", \"class\": " << jstr(f.className)
          << ", \"objectName\": " << jstr(f.objectName) << ", \"windowTitle\": " << jstr(f.windowTitle)
          << ", \"visible\": " << (f.visible ? "true" : "false")
          << ", \"x\": " << f.x << ", \"y\": " << f.y << ", \"w\": " << f.w << ", \"h\": " << f.h
          << ", \"widgetCount\": " << f.widgetCount << ", \"widgets\": [\n";
        bool firstW = true;
        for (auto& w : f.widgets) {
            if (!firstW) o << ",\n";
            firstW = false;
            o << "      { \"address\": \"" << hx(w.address) << "\", \"class\": " << jstr(w.className)
              << ", \"objectName\": " << jstr(w.objectName) << ", \"text\": " << jstr(w.text)
              << ", \"editText\": " << jstr(w.editText)
              << ", \"x\": " << w.x << ", \"y\": " << w.y << ", \"w\": " << w.w << ", \"h\": " << w.h
              << ", \"visible\": " << (w.visible ? "true" : "false")
              << ", \"hasClickHandler\": " << (w.hasClickHandler ? "true" : "false")
              << ", \"clickHandler\": " << jstr(w.clickHandlerName);
            if (!w.comboItems.empty()) {
                o << ", \"comboItems\": [";
                for (size_t i = 0; i < w.comboItems.size(); i++) {
                    if (i) o << ", ";
                    o << jstr(w.comboItems[i]);
                }
                o << "], \"comboCurrentIndex\": " << w.comboCurrentIndex
                  << ", \"comboCurrentText\": " << jstr(w.comboCurrentText);
            }
            if (!w.connections.empty()) {
                o << ", \"connections\": [";
                bool firstC = true;
                for (auto& c : w.connections) {
                    if (!firstC) o << ", ";
                    firstC = false;
                    o << "{ \"signal\": " << jstr(c.signalSignature)
                      << ", \"slot\": " << jstr(c.slotSignature)
                      << ", \"type\": " << jstr(c.connectionType)
                      << ", \"sender\": \"" << hx(c.sender) << "\", \"receiver\": \"" << hx(c.receiver) << "\" }";
                }
                o << "]";
            }
            if (!w.handlers.empty()) {
                o << ", \"handlers\": [";
                bool firstH = true;
                for (auto& h : w.handlers) {
                    if (!firstH) o << ", ";
                    firstH = false;
                    o << "{ \"kind\": " << jstr(h.kind) << ", \"name\": " << jstr(h.name)
                      << ", \"start\": \"" << hx(h.start) << "\", \"end\": \"" << hx(h.end)
                      << "\", \"module\": " << jstr(h.module) << " }";
                }
                o << "]";
            }
            o << " }";
        }
        o << "\n    ] }";
    }
    o << "\n  ],\n";
    o << "  \"classes\": [\n";
    bool firstC2 = true;
    for (auto& c : r.classes) {
        if (c.className.empty()) continue;
        if (!firstC2) o << ",\n";
        firstC2 = false;
        o << "    { \"class\": " << jstr(c.className)
          << ", \"metaObject\": \"" << hx(c.metaObject) << "\""
          << ", \"metacall\": \"" << hx(c.staticMetacall) << "\""
          << ", \"super\": [";
        for (size_t i = 0; i < c.superChain.size(); i++) {
            if (i) o << ", ";
            o << jstr(c.superChain[i]);
        }
        o << "], \"methods\": [";
        for (size_t i = 0; i < c.methods.size(); i++) {
            if (i) o << ", ";
            o << jstr(c.methods[i].signature.empty() ? c.methods[i].name : c.methods[i].signature);
        }
        o << "] }";
    }
    o << "\n  ]\n";
    o << "}\n";
    return o.str();
}

} // namespace umvpqt
