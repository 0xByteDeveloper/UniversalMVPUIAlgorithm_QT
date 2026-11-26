// UMVPQT GOD STATE — Report (text tree + JSON)
// ============================================================================
//  XPRO report.h tarzi: konsol agaci, dosya raporu, JSON.
// ============================================================================
#pragma once
#include "types.h"
#include <string>

namespace umvpqt {

struct Report {
    // konsol/tree metni uret
    static std::string textTree(const AnalysisReport& r);
    // JSON uret
    static std::string json(const AnalysisReport& r);
    // ozet satiri
    static std::string summary(const AnalysisReport& r);
};

} // namespace umvpqt
