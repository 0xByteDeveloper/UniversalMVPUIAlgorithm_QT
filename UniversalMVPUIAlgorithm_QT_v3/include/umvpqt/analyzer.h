// UMVPQT GOD STATE — Analyzer (GOD STATE Orkestrator)
// ============================================================================
//  Pipeline:
//    1. surec ac + moduller + semboller
//    2. Qt tespiti (cag + tam surum) + layout cozumleme (DB + kalibrasyon)
//    3. QObject instance taramasi (q_ptr invariant)
//    4. Sinif cozumleme (vtable -> sembol / metaobject thunk / RTTI)
//    5. Widget agaci (parent/children) + ozellikler (text, geometry, visible...)
//    6. Event tespiti: Connection walker + metacall disasm + vtable override
//    7. ComboBox item'lari + secili deger
//    8. Rapor (text + JSON + .asm)
//    9. Monitor modu: yeniden tarama + diff (yeni widget/metin degisimi)
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "module.h"
#include "qt_layouts.h"
#include "qt_strings.h"
#include "qt_metaobject.h"
#include "qt_scan.h"
#include "qt_connections.h"
#include "qt_items.h"
#include "disasm.h"

namespace umvpqt {

struct AnalyzeOptions {
    bool live = true;            // bellek taramasi (kapatirsan sadece kod analizi)
    bool code = true;            // metacall disasm + override analizi
    bool textDecode = true;      // QString cozumleme
    std::string asmDir;          // .asm dump dizini (bos = yazma)
    int  monitorMs = 0;          // >0: monitor dongusu kac ms
    int  monitorCount = 0;       // 0: surekli
    size_t maxHeapMb = 256;
};

class Analyzer {
public:
    explicit Analyzer(std::unique_ptr<IProcessReader> proc);
    AnalysisReport run(const AnalyzeOptions& opt);

    // monitor: bir tarama daha + onceki raporla diff
    std::string monitorStep(AnalysisReport& prev, const AnalyzeOptions& opt);

    // parcalar (testler icin public)
    bool setupModules();
    bool detectQt();
    std::vector<Addr> scanInstances();

    IProcessReader& proc() { return *proc_; }
    QtLayouts& layouts() { return L_; }
    ClassRegistry& registry() { return reg_; }
    ModuleTable& modules() { return mt_; }

private:
    std::unique_ptr<IProcessReader> proc_;
    ModuleTable mt_;
    QtLayouts L_;
    QtInfo qt_;
    ClassRegistry reg_;
    std::unique_ptr<MetaObjectParser> moParser_;
    DisasmEngine dis_;
    VirtualSlotMap vslots_;

    void buildTreeAndProperties(AnalysisReport& rpt, const std::vector<Addr>& objs,
                               const AnalyzeOptions& opt);
    void extractEvents(AnalysisReport& rpt, const AnalyzeOptions& opt);
    void extractClassHandlers(AnalysisReport& rpt, const AnalyzeOptions& opt);
    WidgetInfo makeWidget(Addr obj, const MetaClassInfo* ci, const AnalyzeOptions& opt, int depth);
    void fillWidget(WidgetInfo& w, const MetaClassInfo& ci, const AnalyzeOptions& opt);
};

} // namespace umvpqt
