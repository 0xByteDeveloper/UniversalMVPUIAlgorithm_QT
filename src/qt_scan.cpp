// =============================================================================
// UMVP-QT // src/qt_scan.cpp — QObject discovery + tree + widget visuals.
// Invariant chain (XPRO methodology applied to Qt):
//   object --+-- vtable in exec memory
//           +-- vtable[2] = metaObject() thunk --(disasm)--> QMetaObject
//           +-- QMetaObjectPrivate header sane (revision 7..12, counts bounded)
//           +-- object+8 = d_ptr; d_ptr->q_ptr == object        (STRONG)
//           +-- children list parses with bounded count
// =============================================================================
#include "umvpqt/qt_scan.h"
#include "umvpqt/disasm.h"

#include <algorithm>
#include <cstring>

namespace umvpqt {

const char* ObjectScanner::vtableSlotName(int slot) {
    switch (slot) {
    case 0: return "~dtor";
    case 1: return "~dtor(deleting)";
    case 2: return "metaObject";
    case 3: return "qt_metacast";
    case 4: return "qt_metacall";
    case 5: return "event";
    case 6: return "eventFilter";
    case 7: return "timerEvent";
    case 8: return "childEvent";
    case 9: return "customEvent";
    case 10: return "connectNotify";
    case 11: return "disconnectNotify";
    // QWidget virtuals (approximate ordering)
    case 12: return "paintEngine";
    case 13: return "paintEvent";
    case 14: return "mousePressEvent";
    case 15: return "mouseReleaseEvent";
    case 16: return "mouseDoubleClickEvent";
    case 17: return "mouseMoveEvent";
    case 18: return "keyPressEvent";
    case 19: return "keyReleaseEvent";
    case 20: return "focusInEvent";
    case 21: return "focusOutEvent";
    case 22: return "enterEvent";
    case 23: return "leaveEvent";
    case 24: return "moveEvent";
    case 25: return "resizeEvent";
    case 26: return "closeEvent";
    case 27: return "contextMenuEvent";
    case 28: return "wheelEvent";
    case 29: return "actionEvent";
    default: return nullptr;
    }
}

bool ObjectScanner::plausibleQStringHeader(Address dataPtr) const {
    // Qt5: QArrayData header {ref(4) size(4) alloc(4) pad offset(8@16)}
    if (L_.stringdata_kind == 0) {
        int32_t size = 0;
        int64_t offset = 0;
        if (!r_.readI32(dataPtr + L_.str_hdr_size, &size)) return false;
        if (!r_.read(dataPtr + L_.str_hdr_offset, &offset, 8)) return false;
        if (size < 0 || size > 4096) return false;
        if (offset < 0 || offset > 0x1000) return false;
        return true;
    }
    return true;   // Qt6 string object is validated by decode itself
}

bool ObjectScanner::decodeQStringAt(Address strObj, std::string* out) const {
    if (!strObj) return false;
    if (L_.stringdata_kind == 0) {
        // Qt5: { QStringData* d }
        Address d = r_.readPtr(strObj);
        if (!r_.isReadable(d)) return false;
        int32_t size = 0;
        int64_t offset = 0;
        if (!r_.readI32(d + L_.str_hdr_size, &size)) return false;
        if (!r_.read(d + L_.str_hdr_offset, &offset, 8)) return false;
        if (size <= 0 || size > 4096) return false;
        Address chars = d + (Address)offset;
        if (!r_.isReadable(chars)) return false;
        std::vector<char16_t> buf((size_t)size);
        if (!r_.read(chars, buf.data(), (size_t)size * 2)) return false;
        *out = utf16_to_utf8(buf.data(), (size_t)size);
    } else {
        // Qt6: { d, ptr, size }
        Address ptr = r_.readPtr(strObj + L_.str_ptr);
        int64_t size = 0;
        if (!r_.read(strObj + L_.str_size, &size, 8)) return false;
        if (size <= 0 || size > 4096) return false;
        if (!r_.isReadable(ptr)) return false;
        std::vector<char16_t> buf((size_t)size);
        if (!r_.read(ptr, buf.data(), (size_t)size * 2)) return false;
        *out = utf16_to_utf8(buf.data(), (size_t)size);
    }
    return looks_like_text(*out);
}

std::string ObjectScanner::readObjectName(Address d) const {
    std::string s;
    Address extra = r_.readPtr(d + L_.priv_extra);
    if (!extra || !r_.isReadable(extra)) return s;
    for (int off : {L_.extra_objectname, L_.extra_objectname_alt}) {
        if (off < 0) continue;
        Address strObj = extra + off;
        if (decodeQStringAt(strObj, &s)) return s;
    }
    return s;
}

std::vector<Address> ObjectScanner::childrenOf(const DiscoveredObject& o) const {
    std::vector<Address> out;
    readChildrenList(o.d_ptr, &out);
    return out;
}

bool ObjectScanner::readChildrenList(Address d, std::vector<Address>* out) const {
    if (!out) return false;
    out->clear();
    Address childrenField = d + L_.obj_children;
    if (L_.list_ptr >= 0) {
        // Qt6: QArrayDataPointer { d, ptr, size } inline at the field
        Address ptr = r_.readPtr(childrenField + L_.list_ptr);
        int64_t size = 0;
        if (!r_.read(childrenField + L_.list_size, &size, 8)) return false;
        if (size < 0 || size > 4096) return false;
        if (!ptr && size == 0) return true;
        if (!r_.isReadable(ptr)) return false;
        for (int64_t i = 0; i < size; ++i) {
            Address child = r_.readPtr(ptr + (Address)i * 8);
            if (child && r_.isReadable(child)) out->push_back(child);
            else return false;   // invariant violation
        }
        return true;
    }
    // Qt5: QList { Data* d } ; nodes at d+16+8*(begin+i), size = end-begin
    Address ld = r_.readPtr(childrenField);
    if (!ld) return true;   // empty/null list
    if (!r_.isReadable(ld)) return false;
    int32_t begin = 0, end = 0;
    if (!r_.readI32(ld + L_.list_begin, &begin)) return false;
    if (!r_.readI32(ld + L_.list_end, &end)) return false;
    if (begin < 0 || end < begin || end - begin > 4096) return false;
    for (int32_t i = begin; i < end; ++i) {
        Address child = r_.readPtr(ld + L_.list_array + (Address)(i - 0) * 8);
        if (child && r_.isReadable(child)) out->push_back(child);
        else if (child) return false;
    }
    return true;
}

bool ObjectScanner::readWidgetData(Address object, DiscoveredObject* o) const {
    // QWidget::data at +24 (QObject 16 + QPaintDevice 8); fallback scan.
    for (int cand : {L_.qw_data_ptr, L_.qw_data_ptr == 24 ? 32 : 24, 16}) {
        Address data = r_.readPtr(object + cand);
        if (!data || !r_.isReadable(data)) continue;
        int32_t crect[4] = {0};
        if (!r_.read(data + L_.qwd_crect, crect, 16)) continue;
        int32_t x1 = crect[0], y1 = crect[1], x2 = crect[2], y2 = crect[3];
        if (x2 < x1 || y2 < y1) continue;
        if ((x2 - x1 + 1) > 16384 || (y2 - y1 + 1) > 16384) continue;
        uint64_t winid = 0;
        r_.readU64(data + L_.qwd_winid, &winid);
        int32_t flags = 0;
        r_.readI32(data + L_.qwd_flags, &flags);
        uint32_t wordA = 0;
        r_.readU32(data + L_.qwd_crect - 8, &wordA);   // bitfield pack before crect
        o->rect = Rect{x1, y1, x2 - x1 + 1, y2 - y1 + 1};
        o->winId = winid;
        o->windowFlags = flags;
        o->inShow = (wordA >> 10) & 1;   // in_show bit
        o->hasWidgetData = true;
        return true;
    }
    return false;
}

void ObjectScanner::heuristics(DiscoveredObject* o) const {
    // Pure-memory text/combo best-effort scan of the private tail region.
    if (!o || !o->d_ptr) return;
    const bool wantsText = o->classChain.size() >= 2 &&
        (o->classChain[0] == "QPushButton" || o->classChain[0] == "QCheckBox" ||
         o->classChain[0] == "QLabel" || o->classChain[0] == "MyButton" ||
         std::find(o->classChain.begin() + 1, o->classChain.end(), "QAbstractButton") != o->classChain.end());
    const bool isCombo = o->className == "QComboBox";
    if (!wantsText && !isCombo) return;

    // scan window right after QObjectPrivate
    const size_t W = 256;
    std::vector<Address> strObjs;
    if (L_.stringdata_kind == 0) {
        // Qt5: candidate QString objects are 8-byte {d} — scan for pointers whose
        // target looks like a QArrayData header
        for (int off = L_.priv_sizeof; off < (int)(L_.priv_sizeof + W); off += 8) {
            Address p = r_.readPtr(o->d_ptr + off);
            if (!p || !r_.isReadable(p)) continue;
            std::string s;
            if (decodeQStringAt(o->d_ptr + off, &s)) {
                if (wantsText && o->text.empty() && !s.empty() &&
                    s != o->objectName) {
                    o->text = s;
                    o->textConfidence = 70;
                }
                strObjs.emplace_back(o->d_ptr + off);
            }
        }
    } else {
        // Qt6: QString objects are 24 bytes {d,ptr,size} inline in the struct
        for (int off = L_.priv_sizeof; off + 24 <= (int)(L_.priv_sizeof + W); off += 8) {
            std::string s;
            if (decodeQStringAt(o->d_ptr + off, &s)) {
                if (wantsText && o->text.empty() && !s.empty() && s != o->objectName) {
                    o->text = s;
                    o->textConfidence = 70;
                }
                strObjs.emplace_back(o->d_ptr + off);
            }
        }
    }
    if (isCombo) {
        // combo private tail: {int currentIndex; int count; QString items[]} heuristic
        for (int off = L_.priv_sizeof; off + 8 <= (int)(L_.priv_sizeof + W); off += 4) {
            int32_t idx = 0, cnt = 0;
            if (!r_.readI32(o->d_ptr + off, &idx)) break;
            if (!r_.readI32(o->d_ptr + off + 4, &cnt)) break;
            if (idx < 0 || idx > 64 || cnt < 1 || cnt > 64) continue;
            std::vector<std::string> items;
            bool ok = true;
            for (int i = 0; i < cnt; ++i) {
                Address itemStr = o->d_ptr + off + 8 + (Address)i * L_.str_obj_size;
                std::string s;
                if (!decodeQStringAt(itemStr, &s)) { ok = false; break; }
                items.push_back(s);
            }
            if (ok && (size_t)idx < items.size()) {
                o->comboItems = items;
                o->comboCurrentIndex = idx;
                o->comboCurrentText = items[(size_t)idx];
                o->comboConfidence = 55;
                return;
            }
        }
        // fallback: consecutive QString objects as items
        if (strObjs.size() >= 2) {
            for (size_t i = 0; i + 1 < strObjs.size(); ++i) {
                if (strObjs[i + 1] - strObjs[i] != (Address)L_.str_obj_size) continue;
                std::vector<std::string> items;
                for (size_t k = i; k < strObjs.size() && strObjs[k] - strObjs[i] == (Address)(L_.str_obj_size * (k - i)); ++k) {
                    std::string s;
                    if (!decodeQStringAt(strObjs[k], &s)) break;
                    items.push_back(s);
                }
                if (items.size() >= 2) {
                    o->comboItems = items;
                    o->comboConfidence = 35;
                    return;
                }
            }
        }
    }
}

std::optional<DiscoveredObject> ObjectScanner::validateObject(Address object) {
    if (!object || !r_.isReadable(object)) return std::nullopt;
    DiscoveredObject o;
    o.object = object;

    // 1. vtable
    Address vtable = r_.readPtr(object);
    if (!vtable || !r_.isExecutable(vtable)) return std::nullopt;
    o.vtable = vtable;

    // 2. vtable[2] -> metaObject() thunk -> static QMetaObject (disassembly)
    Address thunk = r_.readPtr(vtable + 2 * 8);
    if (!thunk || !r_.isExecutable(thunk)) return std::nullopt;
    Address mo = resolve_metaobject_thunk(r_, thunk);
    if (!mo || !r_.isReadable(mo)) return std::nullopt;
    o.metaObject = mo;

    // 3. QMetaObjectPrivate header sanity
    int rev, cls, mc, md, pc, pd, sc;
    if (!mr_.parseHeader(mo, &rev, &cls, &mc, &md, &pc, &pd, &sc)) return std::nullopt;

    // 4. d_ptr + q_ptr == object (STRONG INVARIANT)
    Address d = r_.readPtr(object + 8);
    if (!d || !r_.isWritable(d) || !r_.isReadable(d)) return std::nullopt;
    if (r_.readPtr(d + L_.obj_qptr) != object) return std::nullopt;
    o.d_ptr = d;

    // 5. bitfields / parent / children
    uint32_t bits = 0;
    r_.readU32(d + L_.obj_bits, &bits);
    o.isWidget = bits & 1;
    o.isWindow = (bits >> 6) & 1;
    o.parent = r_.readPtr(d + L_.obj_parent);
    o.className = mr_.decodeString(mo, cls);
    o.classChain = mr_.classChain(mo);
    if (o.className.empty()) return std::nullopt;
    if (!readChildrenList(d, &o.children)) o.children.clear();
    o.objectName = readObjectName(d);

    // 6. widget visuals
    if (o.isWidget) {
        bool isWidgetClass = std::find(o.classChain.begin(), o.classChain.end(),
                                      "QWidget") != o.classChain.end();
        if (isWidgetClass || o.classChain.empty()) readWidgetData(object, &o);
    }

    heuristics(&o);
    return o;
}

std::optional<DiscoveredObject> ObjectScanner::parseObjectNode(Address object) const {
    // const version used by tests
    return const_cast<ObjectScanner*>(this)->validateObject(object);
}

std::vector<DiscoveredObject> ObjectScanner::scanObjects(size_t maxObjects) {
    std::vector<DiscoveredObject> found;
    std::set<Address> seen;
    // candidate sweep over writable regions
    for (const MemoryRegion& reg : r_.regions()) {
        if (!(reg.perms & 2)) continue;              // need W
        if (reg.end - reg.start > (1ULL << 32)) continue;
        const size_t CHUNK = 1 << 20;               // 1 MB
        for (Address chunk = reg.start; chunk < reg.end; chunk += CHUNK) {
            Address lo = chunk, hi = std::min(chunk + CHUNK, reg.end);
            std::vector<uint8_t> buf((size_t)(hi - lo));
            if (!r_.read(lo, buf.data(), buf.size())) continue;
            for (size_t off = 0; off + 8 <= buf.size(); off += 8) {
                uint64_t vtable;
                memcpy(&vtable, buf.data() + off, 8);
                Address object = lo + off;
                if (!vtable || !r_.isExecutable((Address)vtable)) continue;
                auto cand = validateObject(object);
                if (!cand) continue;
                if (!seen.insert(object).second) continue;
                found.push_back(*cand);
                if (found.size() >= maxObjects) return found;
            }
        }
    }
    return found;
}

std::vector<std::string> ObjectScanner::detectVtableOverrides(
    const std::vector<DiscoveredObject>& objects, const DiscoveredObject& obj) {
    // Find any object whose metaObject == super(metaObject of obj's class) ->
    // that object's vtable is the base-class vtable; compare slots.
    std::vector<std::string> out;
    if (obj.classChain.size() < 2) return out;
    Address superMeta = 0;
    // super metaobject = meta of chain[1]
    std::vector<Address> chain = mr_.metaChain(obj.metaObject);
    if (chain.size() >= 2) superMeta = chain[1];
    if (!superMeta) return out;
    const Address baseVtable = 0;
    for (const DiscoveredObject& other : objects) {
        if (other.object == obj.object) continue;
        if (other.metaObject != superMeta) continue;   // direct instance of super
        for (int slot = 5; slot < 64; ++slot) {   // 2..4 (metaObject/qt_metacast/qt_metacall) may differ per class legitimately
            Address mine = r_.readPtr(obj.vtable + (Address)slot * 8);
            Address theirs = r_.readPtr(other.vtable + (Address)slot * 8);
            if (!mine || !theirs || mine == theirs) continue;
            if (!r_.isExecutable(mine) || !r_.isExecutable(theirs)) continue;
            const char* name = vtableSlotName(slot);
            out.push_back(name ? std::string(name) : ("virtual#" + std::to_string(slot)));
        }
        return out;   // one base reference is enough
    }
    return out;
}

} // namespace umvpqt
