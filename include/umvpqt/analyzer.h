// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/analyzer.h
// GOD STATE orchestrator: version detection -> heap sweep -> object tree ->
// connection graph -> handler disassembly -> forms/active form -> report.
// =============================================================================
#pragma once
#include <memory>

#include "process.h"
#include "qt_invoke.h"
#include "qt_layout.h"
#include "qt_scan.h"
#include "qt_signals.h"
#include "types.h"

namespace umvpqt {

struct AnalyzerOptions {
    bool live = true;          // memory scan on
    bool code = true;          // disassembly/handler resolution on
    bool invoke = false;       // enable executor-based property reads / calls
    QtFamily familyOverride = QtFamily::Unknown;
    size_t maxObjects = 200000;
};

class Analyzer {
public:
    Analyzer(IProcessReader& r, IRemoteExecutor* ex = nullptr)
        : r_(r), ex_(ex) {}

    AnalysisReport analyze(const AnalyzerOptions& opt = AnalyzerOptions());

    // family detection (module names + layout invariant probing)
    QtVersion detectQtVersion();

private:
    WidgetInfo buildWidgetInfo(const DiscoveredObject& o, int depth);

    IProcessReader& r_;
    IRemoteExecutor* ex_;
};

} // namespace umvpqt
