// =============================================================================
// UMVP-QT // src/report.cpp — text/JSON/asm output.
// =============================================================================
#include "umvpqt/report.h"

#include <cstdio>
#include <fstream>
#include <sstream>

namespace umvpqt {

namespace {
std::string jesc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", (unsigned char)c);
                o += b;
            } else o += c;
        }
    }
    return o;
}

void jconn(std::ostringstream& j, const ConnectionInfo& c) {
    j << "{\"connection\":" << c.connection
      << ",\"signal\":\"" << jesc(c.signalName) << "\""
      << ",\"signalIndex\":" << c.signalIndex
      << ",\"receiver\":" << c.receiver
      << ",\"slot\":\"" << jesc(c.slotName) << "\""
      << ",\"slotOwner\":\"" << jesc(c.slotOwnerClass) << "\""
      << ",\"type\":\"" << c.connectionType << "\""
      << ",\"isSlotObject\":" << (c.isSlotObject ? "true" : "false")
      << ",\"slotFunction\":" << c.slotFunction << "}";
}

void jhandler(std::ostringstream& j, const HandlerInfo& h) {
    j << "{\"method\":\"" << jesc(h.ownerClass + "::" + h.methodName) << "\""
      << ",\"entry\":" << h.entry
      << ",\"range\":[\"" << h.base << "\",\"" << h.end << "\"]"
      << ",\"via\":\"" << jesc(h.viaKind) << "\""
      << ",\"confidence\":" << h.confidence
      << ",\"disasmLines\":" << h.disasm.lines.size() << "}";
}

void jwidget(std::ostringstream& j, const WidgetInfo& w, int depth) {
    j << "{\n\"object\":" << w.object
      << ",\"class\":\"" << jesc(w.className) << "\""
      << ",\"chain\":\"" << jesc([&] {
            std::string s;
            for (size_t i = 0; i < w.classChain.size(); ++i) {
                if (i) s += "->";
                s += w.classChain[i];
            }
            return s;
        }()) << "\""
      << ",\"name\":\"" << jesc(w.objectName) << "\""
      << ",\"text\":\"" << jesc(w.text) << "\""
      << ",\"textConfidence\":" << w.textConfidence
      << ",\"rect\":{\"x\":" << w.rect.x << ",\"y\":" << w.rect.y
      << ",\"w\":" << w.rect.w << ",\"h\":" << w.rect.h << "}"
      << ",\"winId\":" << w.winId
      << ",\"depth\":" << depth
      << ",\"visible\":" << (w.visible ? "true" : "false")
      << ",\"isWidget\":" << (w.isWidget ? "true" : "false")
      << ",\"eventHandlers\":" << (w.hasEventHandlers ? "true" : "false")
      << ",\"staticMetacall\":" << w.staticMetacall
      << ",\"combo\":{\"items\":[";
    for (size_t i = 0; i < w.comboItems.size(); ++i) {
        if (i) j << ",";
        j << "\"" << jesc(w.comboItems[i]) << "\"";
    }
    j << "],\"currentIndex\":" << w.comboCurrentIndex
      << ",\"currentText\":\"" << jesc(w.comboCurrentText) << "\""
      << ",\"confidence\":" << w.comboConfidence << "}"
      << ",\"connections\":[";
    for (size_t i = 0; i < w.outgoingConnections.size(); ++i) {
        if (i) j << ",";
        jconn(j, w.outgoingConnections[i]);
    }
    j << "],\"handlers\":[";
    for (size_t i = 0; i < w.handlers.size(); ++i) {
        if (i) j << ",";
        jhandler(j, w.handlers[i]);
    }
    j << "],\"overrides\":[";
    for (size_t i = 0; i < w.overriddenVirtuals.size(); ++i) {
        if (i) j << ",";
        j << "\"" << jesc(w.overriddenVirtuals[i]) << "\"";
    }
    j << "]}";
}

void jform(std::ostringstream& j, const FormInfo& f, int idx) {
    j << "{\n\"index\":" << idx
      << ",\"class\":\"" << jesc(f.className) << "\""
      << ",\"name\":\"" << jesc(f.objectName) << "\""
      << ",\"object\":" << f.object
      << ",\"active\":" << (f.isActive ? "true" : "false")
      << ",\"visible\":" << (f.visible ? "true" : "false")
      << ",\"winId\":" << f.winId
      << ",\"widgetCount\":" << f.widgetCount
      << ",\"widgets\":[";
    for (size_t i = 0; i < f.widgets.size(); ++i) {
        if (i) j << ",";
        jwidget(j, f.widgets[i], f.widgets[i].depth);
    }
    j << "]}";
}
} // namespace

std::string report_text(const AnalysisReport& rep) {
    std::ostringstream t;
    t << "==============================================================================\n";
    t << "UMVP-QT // UniversalMVPUIAlgorithm_QT — GOD STATE QT UI ANALYSIS\n";
    t << "Qt5 | Qt6 — PDB YOK, saf bellek + derin disassembly\n";
    t << "==============================================================================\n";
    t << "Hedef        : " << rep.process.name << " (PID " << rep.process.pid << ")"
       << (rep.process.arch == Arch::X64 ? " [x64]" : rep.process.arch == Arch::X86 ? " [x86]" : "")
       << "\n";
    t << "Qt           : " << rep.qt.major << "." << rep.qt.minor
       << " ailesi (revision " << rep.qt.revision << ")"
       << (rep.qt.module.empty() ? "" : "  modul: " + rep.qt.module) << "\n";
    t << "Dogrulanmis QObject : " << rep.verifiedQObjects
       << "  | baglanti: " << rep.connectionCount
       << "  | handler: " << rep.handlerCount << "\n";
    t << "--- FORMLAR: " << rep.forms.size() << " ";
    for (size_t i = 0; i < 58; ++i) t << "-";
    t << "\n";
    for (size_t fi = 0; fi < rep.forms.size(); ++fi) {
        const FormInfo& f = rep.forms[fi];
        t << "[" << fi << "] \"" << (f.objectName.empty() ? f.className : f.objectName)
          << "\"  (" << f.className << ")"
          << (f.isActive ? "  [AKTIF]" : "")
          << (f.visible ? " [GORUNUR]" : " [GIZLI]") << "\n";
        t << "    nesne=0x" << std::hex << f.object << std::dec
          << "  rect=(" << f.rect.x << "," << f.rect.y << "," << f.rect.w << "," << f.rect.h << ")"
          << "  winId=0x" << std::hex << f.winId << std::dec << "\n";
        t << "    widget'lar (" << f.widgetCount << "):\n";
        for (size_t wi = 0; wi < f.widgets.size(); ++wi) {
            const WidgetInfo& w = f.widgets[wi];
            int depth = w.depth < 0 ? 0 : (w.depth > 24 ? 24 : w.depth);
            std::string pad((size_t)depth * 2 + 6, ' ');
            t << pad << wi + 1 << ". " << w.className;
            if (!w.objectName.empty()) t << " \"" << w.objectName << "\"";
            if (!w.text.empty()) t << "  text=\"" << w.text << "\""
                                   << " (guven %" << w.textConfidence << ")";
            if (w.hasRect)
                t << "  rect=(" << w.rect.x << "," << w.rect.y << "," << w.rect.w
                  << "," << w.rect.h << ")";
            if (w.className == "QComboBox" && !w.comboItems.empty()) {
                t << "\n" << pad << "   ogeler: ";
                for (size_t ci = 0; ci < w.comboItems.size(); ++ci) {
                    if (ci) t << "|";
                    t << w.comboItems[ci];
                }
                t << "  secili: " << (w.comboCurrentIndex >= 0 ? w.comboCurrentText : "-");
            }
            t << "\n";
            for (const ConnectionInfo& ci : w.outgoingConnections) {
                std::string cpad((size_t)depth * 2 + 9, ' ');
                t << cpad << "olay: " << ci.signalName << " -> "
                  << (ci.slotName.empty() ? std::string("<functor>") : ci.slotName)
                  << " [" << ci.connectionType << "]"
                  << "  handler=0x" << std::hex << ci.slotFunction << std::dec << "\n";
            }
            if (w.outgoingConnections.empty() && w.handlers.empty() &&
                w.overriddenVirtuals.empty()) {
                std::string cpad((size_t)depth * 2 + 9, ' ');
                t << cpad << "olay: YOK (bagli handler yok)\n";
            }
            for (const std::string& ov : w.overriddenVirtuals) {
                std::string cpad((size_t)depth * 2 + 9, ' ');
                t << cpad << "override: " << ov << "\n";
            }
            for (const HandlerInfo& h : w.handlers) {
                std::string hpad((size_t)depth * 2 + 9, ' ');
                t << hpad << "handler kod blogu: 0x" << std::hex << h.base << "..0x"
                  << h.end << std::dec << " (" << h.disasm.instructionCount
                  << " komut)  [" << h.viaKind << ", guven %" << h.confidence << "]\n";
            }
        }
    }
    return t.str();
}

std::string report_json(const AnalysisReport& rep) {
    std::ostringstream j;
    j << "{\n\"process\":{\"pid\":" << rep.process.pid
      << ",\"name\":\"" << jesc(rep.process.name) << "\"},\n";
    j << "\"qt\":{\"family\":" << (int)rep.qt.family
      << ",\"revision\":" << rep.qt.revision
      << ",\"major\":" << rep.qt.major
      << ",\"minor\":" << rep.qt.minor
      << ",\"module\":\"" << jesc(rep.qt.module) << "\"},\n";
    j << "\"stats\":{\"objects\":" << rep.objectCount
      << ",\"verifiedQObjects\":" << rep.verifiedQObjects
      << ",\"connections\":" << rep.connectionCount
      << ",\"handlers\":" << rep.handlerCount << "},\n";
    j << "\"activeForm\":" << rep.activeForm << ",\n";
    j << "\"forms\":[";
    for (size_t i = 0; i < rep.forms.size(); ++i) {
        if (i) j << ",";
        jform(j, rep.forms[i], (int)i);
    }
    j << "],\n\"allObjects\":[";
    for (size_t i = 0; i < rep.allObjects.size(); ++i) {
        if (i) j << ",";
        jwidget(j, rep.allObjects[i], rep.allObjects[i].depth);
    }
    j << "]\n}\n";
    return j.str();
}

std::string handler_asm(const HandlerInfo& h) {
    std::ostringstream a;
    a << "; handler " << h.ownerClass << "::" << h.methodName << "\n";
    a << "; range 0x" << std::hex << h.base << " .. 0x" << h.end << std::dec
      << " (" << (h.end - h.base) << " bytes)\n";
    a << "; via   " << h.viaKind << " 0x" << std::hex << h.via << std::dec << "\n";
    for (const std::string& line : h.disasm.lines) a << line << "\n";
    return a.str();
}

std::vector<std::string> write_asm_dir(const AnalysisReport& rep, const std::string& dir) {
    std::vector<std::string> files;
    int n = 0;
    for (const FormInfo& f : rep.forms) {
        for (const WidgetInfo& w : f.widgets) {
            for (const HandlerInfo& h : w.handlers) {
                char name[128];
                std::snprintf(name, sizeof name, "%s/handler_%03d.asm", dir.c_str(), ++n);
                std::ofstream out(name);
                if (!out) continue;
                out << handler_asm(h);
                files.push_back(name);
            }
        }
    }
    return files;
}

} // namespace umvpqt
