// =============================================================================
// UMVP-QT // src/qt_meta.cpp — QMetaObject decoder implementation.
// String formats verified against qtbase 5.15 / 6.8 qmetaobject.cpp:
//   Qt5: stringdata = QByteArrayData entries (24B each): size@+4, offset@+16,
//        chars at entry+offset (UTF-16).
//   Qt6: stringdata = uint[] pairs: [2i]=offset (bytes from array start),
//        [2i+1]=length; chars at (char*)stringdata + offset.
// Method entries: Qt5 5 ints / Qt6 6 ints (name, argc, params, tag, flags[, metaTypeOffset]).
// =============================================================================
#include "umvpqt/qt_meta.h"

#include <cstring>

namespace umvpqt {

std::string utf16_to_utf8(const char16_t* s, size_t n) {
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        uint32_t c = (uint16_t)s[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
            uint32_t c2 = (uint16_t)s[i + 1];
            if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) out += (char)c;
        else if (c < 0x800) {
            out += (char)(0xC0 | (c >> 6));
            out += (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += (char)(0xE0 | (c >> 12));
            out += (char)(0x80 | ((c >> 6) & 0x3F));
            out += (char)(0x80 | (c & 0x3F));
        } else {
            out += (char)(0xF0 | (c >> 18));
            out += (char)(0x80 | ((c >> 12) & 0x3F));
            out += (char)(0x80 | ((c >> 6) & 0x3F));
            out += (char)(0x80 | (c & 0x3F));
        }
    }
    return out;
}

bool looks_like_text(const std::string& s) {
    if (s.empty() || s.size() > 512) return false;
    size_t printable = 0;
    for (char c : s) {
        if ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\t' ||
            (uint8_t)c >= 0x80)  // UTF-8 multibyte
            ++printable;
    }
    return printable == s.size();
}

std::string MetaObjectReader::decodeString(Address mo, int index) const {
    if (!mo || index < 0 || index > 0x100000) return {};
    Address stringdata = r_.readPtr(mo + L_.mo_stringdata);
    if (!r_.isReadable(stringdata)) return {};

    if (L_.stringdata_kind == 0) {
        // Qt5: entries of 24 bytes; size@+4; offset@+16; chars at entry+offset.
        Address entry = stringdata + (Address)index * 24;
        int32_t size = 0;
        int64_t offset = 0;
        if (!r_.readI32(entry + 4, &size)) return {};
        if (!r_.read(entry + 16, &offset, 8)) return {};
        if (size < 0 || size > 0x10000) return {};
        if (size == 0) return std::string();
        Address chars = entry + (Address)offset;
        if (!r_.isReadable(chars) && size) return {};
        std::vector<char16_t> buf((size_t)size);
        if (size && !r_.read(chars, buf.data(), (size_t)size * 2)) return {};
        return utf16_to_utf8(buf.data(), (size_t)size);
    }
    // Qt6: uint pairs.
    uint32_t off = 0, len = 0;
    if (!r_.readU32(stringdata + (Address)(2 * index) * 4, &off)) return {};
    if (!r_.readU32(stringdata + (Address)(2 * index + 1) * 4, &len)) return {};
    if (len > 0x10000) return {};
    if (len == 0) return std::string();
    Address chars = stringdata + off;
    std::vector<char16_t> buf((size_t)len);
    if (!r_.read(chars, buf.data(), (size_t)len * 2)) return {};
    return utf16_to_utf8(buf.data(), (size_t)len);
}

bool MetaObjectReader::parseHeader(Address mo, int* revision, int* classNameIdx,
                                    int* methodCount, int* methodDataIdx,
                                    int* propertyCount, int* propertyDataIdx,
                                    int* signalCount) const {
    Address data = r_.readPtr(mo + L_.mo_data);
    if (!r_.isReadable(data)) return false;
    int32_t hdr[14];
    if (!r_.read(data, hdr, sizeof(hdr))) return false;
    *revision = hdr[0];
    *classNameIdx = hdr[1];
    *methodCount = hdr[5];
    *methodDataIdx = hdr[6];
    *propertyCount = hdr[7];
    *propertyDataIdx = hdr[8];
    *signalCount = hdr[13];
    if (*revision < 7 || *revision > 12) return false;     // moc rev 7..12
    if (*methodCount < 0 || *methodCount > 4096) return false;
    if (*signalCount < 0 || *signalCount > *methodCount) return false;
    if (*propertyCount < 0 || *propertyCount > 4096) return false;
    return true;
}

std::vector<Address> MetaObjectReader::metaChain(Address mo) const {
    std::vector<Address> chain;
    Address cur = mo;
    for (int depth = 0; cur && depth < 24; ++depth) {
        if (!r_.isReadable(cur)) break;
        chain.push_back(cur);
        cur = r_.readPtr(cur + L_.mo_superdata);
    }
    return chain;   // derived -> base
}

std::vector<std::string> MetaObjectReader::classChain(Address mo) const {
    std::vector<std::string> names;
    for (Address m : metaChain(mo)) {
        int rev, cls, mc, md, pc, pd, sc;
        if (!parseHeader(m, &rev, &cls, &mc, &md, &pc, &pd, &sc)) break;
        std::string n = decodeString(m, cls);
        if (n.empty()) break;
        names.push_back(n);
    }
    return names;   // derived -> base
}

int MetaObjectReader::methodCountOf(Address mo) const {
    int rev, cls, mc, md, pc, pd, sc;
    if (!parseHeader(mo, &rev, &cls, &mc, &md, &pc, &pd, &sc)) return 0;
    return mc;
}

int MetaObjectReader::signalCountOf(Address mo) const {
    int rev, cls, mc, md, pc, pd, sc;
    if (!parseHeader(mo, &rev, &cls, &mc, &md, &pc, &pd, &sc)) return 0;
    return sc;
}

int MetaObjectReader::methodOffset(Address mo) const {
    int off = 0;
    auto chain = metaChain(mo);          // derived -> base
    for (auto it = chain.begin() + 1; it != chain.end(); ++it)
        off += methodCountOf(*it);
    return off;
}

int MetaObjectReader::signalOffset(Address mo) const {
    int off = 0;
    auto chain = metaChain(mo);          // derived -> base
    for (auto it = chain.begin() + 1; it != chain.end(); ++it)
        off += signalCountOf(*it);
    return off;
}

std::optional<MetaClass> MetaObjectReader::parseMetaClass(Address mo) const {
    MetaClass c;
    c.metaObject = mo;
    int rev, cls, mc, md, pc, pd, sc;
    if (!parseHeader(mo, &rev, &cls, &mc, &md, &pc, &pd, &sc)) return std::nullopt;
    c.revision = rev;
    c.methodCount = mc;
    c.signalCount = sc;
    c.propertyCount = pc;
    c.className = decodeString(mo, cls);
    if (c.className.empty()) return std::nullopt;
    c.superMetaObject = r_.readPtr(mo + L_.mo_superdata);
    if (c.superMetaObject && r_.isReadable(c.superMetaObject)) {
        int r2, cls2, mc2, md2, pc2, pd2, sc2;
        if (parseHeader(c.superMetaObject, &r2, &cls2, &mc2, &md2, &pc2, &pd2, &sc2))
            c.superClassName = decodeString(c.superMetaObject, cls2);
    }

    Address data = r_.readPtr(mo + L_.mo_data);
    if (!r_.isReadable(data)) return std::nullopt;
    const int ipm = L_.mop_ints_per_method;

    // methods (signals first in methodData)
    for (int i = 0; i < mc && i < 512; ++i) {
        Address entry = data + (Address)(md + i * ipm) * 4;
        uint32_t nameIdx = 0, argc = 0, params = 0, tag = 0, flags = 0;
        if (!r_.readU32(entry, &nameIdx)) break;
        if (!r_.readU32(entry + 4, &argc)) break;
        if (!r_.readU32(entry + 8, &params)) break;
        if (!r_.readU32(entry + 12, &tag)) break;
        if (!r_.readU32(entry + 16, &flags)) break;
        MetaMethod m;
        m.name = decodeString(mo, (int)nameIdx);
        m.flags = (int)flags;
        m.localIndex = i;
        m.absoluteIndex = methodOffset(mo) + i;
        m.ownerClass = c.className;
        m.metaObject = mo;
        m.staticMetacall = r_.readPtr(mo + L_.mo_static_metacall);
        switch (flags & 0x0c) {
        case 0x04: m.type = MetaMethodType::Signal; break;
        case 0x08: m.type = MetaMethodType::Slot; break;
        case 0x0c: m.type = MetaMethodType::Constructor; break;
        default:   m.type = MetaMethodType::Method; break;
        }
        switch (flags & 0x03) {
        case 0x00: m.access = "private"; break;
        case 0x01: m.access = "protected"; break;
        default:   m.access = "public"; break;
        }
        if (argc > 64) argc = 0;   // defensive
        for (uint32_t a = 0; a < argc; ++a) {
            uint32_t tinfo = 0;
            if (!r_.readU32(data + (Address)(params + 1 + a) * 4, &tinfo)) break;
            if (tinfo & 0x80000000)
                m.paramTypes.push_back(decodeString(mo, (int)(tinfo & 0x7FFFFFFF)));
            else
                m.paramTypes.push_back("#" + std::to_string(tinfo));
        }
        std::string sig = m.name + "(";
        for (size_t a = 0; a < m.paramTypes.size(); ++a) {
            if (a) sig += ",";
            sig += m.paramTypes[a];
        }
        sig += ")";
        m.signature = sig;
        c.methods.push_back(m);
    }

    // properties (3 ints each)
    for (int i = 0; i < pc && i < 512; ++i) {
        Address entry = data + (Address)(pd + i * 3) * 4;
        uint32_t nameIdx = 0, typeInfo = 0, pflags = 0;
        if (!r_.readU32(entry, &nameIdx)) break;
        if (!r_.readU32(entry + 4, &typeInfo)) break;
        if (!r_.readU32(entry + 8, &pflags)) break;
        MetaProperty p;
        p.name = decodeString(mo, (int)nameIdx);
        if (p.name.empty()) break;
        if (typeInfo & 0x80000000)
            p.type = decodeString(mo, (int)(typeInfo & 0x7FFFFFFF));
        else
            p.type = "#" + std::to_string(typeInfo);
        p.flags = (int)pflags;
        p.readable = (pflags & 0x1) != 0;
        p.writable = (pflags & 0x2) != 0;
        p.localIndex = i;
        p.ownerClass = c.className;
        p.metaObject = mo;
        c.properties.push_back(p);
    }
    return c;
}

bool MetaObjectReader::resolveMethodByAbsIndex(Address mostDerived, int absIndex,
                                               Address* owner, int* localIndex) const {
    std::vector<Address> chain = metaChain(mostDerived);   // derived -> base
    int off = 0;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {   // base -> derived
        int mc = methodCountOf(*it);
        if (absIndex < off + mc) {
            *owner = *it;
            *localIndex = absIndex - off;
            return true;
        }
        off += mc;
    }
    return false;
}

std::vector<MetaMethod> MetaObjectReader::allMethods(Address mostDerived) const {
    std::vector<MetaMethod> out;
    std::vector<Address> chain = metaChain(mostDerived);
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        auto c = parseMetaClass(*it);
        if (!c) break;
        for (auto& m : c->methods) {
            m.absoluteIndex = methodOffset(*it) + m.localIndex;
            out.push_back(m);
        }
    }
    return out;
}

std::vector<MetaProperty> MetaObjectReader::allProperties(Address mostDerived) const {
    std::vector<MetaProperty> out;
    std::vector<Address> chain = metaChain(mostDerived);
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        auto c = parseMetaClass(*it);
        if (!c) break;
        for (auto& p : c->properties) out.push_back(p);
    }
    return out;
}

std::optional<MetaMethod> MetaObjectReader::resolveSignalByAbsIndex(
    Address mostDerived, int sigIndex, Address* owner, int* localIndex) const {
    std::vector<Address> chain = metaChain(mostDerived);   // derived -> base
    int off = 0;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {   // base -> derived
        int sc = signalCountOf(*it);
        if (sigIndex < off + sc) {
            int local = sigIndex - off;
            if (owner) *owner = *it;
            if (localIndex) *localIndex = local;
            auto c = parseMetaClass(*it);
            if (c && local < (int)c->methods.size()) {
                MetaMethod m = c->methods[(size_t)local];
                m.absoluteIndex = methodOffset(*it) + local;
                return m;
            }
            break;
        }
        off += sc;
    }
    return std::nullopt;
}

std::optional<MetaMethod> MetaObjectReader::findMethod(Address mostDerived,
                                                       const std::string& name) const {
    for (const MetaMethod& m : allMethods(mostDerived))
        if (m.name == name) return m;
    return std::nullopt;
}

std::optional<MetaMethod> MetaObjectReader::findMethod(Address mostDerived,
                                                       const std::string& name,
                                                       MetaMethodType type) const {
    for (const MetaMethod& m : allMethods(mostDerived))
        if (m.name == name && m.type == type) return m;
    return std::nullopt;
}

std::optional<MetaProperty> MetaObjectReader::findProperty(Address mostDerived,
                                                           const std::string& name) const {
    for (const MetaProperty& p : allProperties(mostDerived))
        if (p.name == name) return p;
    return std::nullopt;
}

} // namespace umvpqt
