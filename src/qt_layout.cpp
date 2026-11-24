// =============================================================================
// UMVP-QT // src/qt_layout.cpp — runtime layout table accessors.
// Values come from src/qt_layout_db.h (generated; never hand-written).
// =============================================================================
#include "umvpqt/qt_layout.h"
#include "qt_layout_db.h"

namespace umvpqt {

std::string QtVersion::to_string() const {
    if (family == QtFamily::Unknown) return "bilinmeyen Qt ailesi";
    std::string s = family == QtFamily::Qt5 ? "Qt 5" : "Qt 6";
    if (major || minor) {
        s += " (";
        if (major) s += std::to_string(major);
        if (minor) s += "." + std::to_string(minor);
        s += ")";
    }
    if (revision >= 0) s += " moc-revision " + std::to_string(revision);
    if (!module.empty()) s += " modul: " + module;
    return s;
}

const QtLayout* layout_db_qt5_x64() { return &db::QT5_X64; }
const QtLayout* layout_db_qt6_x64() { return &db::QT6_X64; }

const QtLayout* layout_for(QtFamily f) {
    switch (f) {
    case QtFamily::Qt5: return &db::QT5_X64;
    case QtFamily::Qt6: return &db::QT6_X64;
    default: return nullptr;
    }
}

} // namespace umvpqt
