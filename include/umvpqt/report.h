// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/report.h
// Text report (XPRO banner style) + JSON report + per-handler .asm dumps.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "types.h"

namespace umvpqt {

std::string report_text(const AnalysisReport& rep);
std::string report_json(const AnalysisReport& rep);
// one .asm file content per handler
std::string handler_asm(const HandlerInfo& h);

// write all handler asm files into dir; returns filenames
std::vector<std::string> write_asm_dir(const AnalysisReport& rep,
                                       const std::string& dir);

} // namespace umvpqt
