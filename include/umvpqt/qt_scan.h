// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/qt_scan.h
// Live memory scan: QObject discovery via vtable->metaObject()->QMetaObjectPrivate
// invariant chain + q_ptr self-check, object tree reconstruction, objectName
// decode, QWidgetData geometry (crect/winid/flags), vtable override detection
// and best-effort text/combo heuristics for pure-memory mode.
// =============================================================================
#pragma once
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "process.h"
#include "qt_layout.h"
#include "qt_meta.h"
#include "types.h"

namespace umvpqt {

struct DiscoveredObject {
    Address object = 0;
    Address d_ptr = 0;
    Address vtable = 0;
    Address metaObject = 0;
    std::string className;
    std::vector<std::string> classChain;   // derived -> base
    std::string objectName;
    bool isWidget = false, isWindow = false;
    bool deleted = false;
    Address parent = 0;
    std::vector<Address> children;
    // widget visuals
    bool hasWidgetData = false;
    Rect rect;
    uint64_t winId = 0;
    int windowFlags = 0;
    bool inShow = false;
    // heuristics
    std::string text;
    int textConfidence = 0;
    std::vector<std::string> comboItems;
    int comboCurrentIndex = -1;
    std::string comboCurrentText;
    int comboConfidence = 0;
    std::vector<std::string> overriddenVirtuals;
};

class ObjectScanner {
public:
    ObjectScanner(IProcessReader& r, const QtLayout& L) : r_(r), L_(L), mr_(r, L) {}

    // Full heap sweep with invariant validation.
    std::vector<DiscoveredObject> scanObjects(size_t maxObjects = 200000);

    // Single-object structural validation/parse (used by tests and re-checks).
    std::optional<DiscoveredObject> validateObject(Address object);

    // Tree helpers
    std::vector<Address> childrenOf(const DiscoveredObject& o) const;
    std::optional<DiscoveredObject> parseObjectNode(Address object) const;

    // QWidget virtual-name map (approximate; used for override labels)
    static const char* vtableSlotName(int slot);

    // vtable override detection against the base-class vtable (same super meta)
    std::vector<std::string> detectVtableOverrides(
        const std::vector<DiscoveredObject>& objects,
        const DiscoveredObject& obj);

private:
    IProcessReader& r_;
    const QtLayout& L_;
    MetaObjectReader mr_;

    bool readChildrenList(Address d, std::vector<Address>* out) const;
    std::string readObjectName(Address d) const;
    bool decodeQStringAt(Address strObj, std::string* out) const;
    bool readWidgetData(Address object, DiscoveredObject* o) const;
    void heuristics(DiscoveredObject* o) const;
    bool plausibleQStringHeader(Address dataPtr) const;
};

} // namespace umvpqt
