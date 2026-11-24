// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/qt_meta.h
// QMetaObject decoder: class chain, methods (signals/slots), properties,
// string decoding (Qt5 QByteArrayData entries / Qt6 uint pairs), absolute
// signal & method index resolution across the inheritance chain.
// =============================================================================
#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "process.h"
#include "qt_layout.h"
#include "types.h"

namespace umvpqt {

class MetaObjectReader {
public:
    MetaObjectReader(IProcessReader& r, const QtLayout& L) : r_(r), L_(L) {}

    // Decode string #index of a metaobject (both stringdata formats).
    std::string decodeString(Address mo, int index) const;

    // Parse the QMetaObjectPrivate header (14 ints).
    bool parseHeader(Address mo, int* revision, int* classNameIdx, int* methodCount,
                     int* methodDataIdx, int* propertyCount, int* propertyDataIdx,
                     int* signalCount) const;

    // Full local-class decode (methods + properties + super link).
    std::optional<MetaClass> parseMetaClass(Address mo) const;

    // Class chain derived -> base (className strings).
    std::vector<std::string> classChain(Address mo) const;
    std::vector<Address> metaChain(Address mo) const;   // derived -> base metaobjects

    // Absolute method index -> owning metaobject + local index.
    bool resolveMethodByAbsIndex(Address mostDerived, int absIndex,
                                 Address* owner, int* localIndex) const;

    // Absolute SIGNAL index (QObjectPrivate::signalIndex numbering:
    // base classes first) -> owner + local method index + method.
    std::optional<MetaMethod> resolveSignalByAbsIndex(Address mostDerived, int sigIndex,
                                                       Address* owner, int* localIndex) const;

    // Find method by name in the chain (exact name, any type).
    std::optional<MetaMethod> findMethod(Address mostDerived, const std::string& name,
                                         MetaMethodType type) const;
    std::optional<MetaMethod> findMethod(Address mostDerived, const std::string& name) const;

    // Find property by name in the chain.
    std::optional<MetaProperty> findProperty(Address mostDerived, const std::string& name) const;

    // methodOffset of a metaobject (sum of super methodCounts).
    int methodOffset(Address mo) const;
    int signalOffset(Address mo) const;   // sum of super signalCounts
    int methodCountOf(Address mo) const;
    int signalCountOf(Address mo) const;

    // All methods of the full chain (absolute indexed), signals+slots+methods.
    std::vector<MetaMethod> allMethods(Address mostDerived) const;
    std::vector<MetaProperty> allProperties(Address mostDerived) const;

private:
    IProcessReader& r_;
    const QtLayout& L_;
};

// UTF-16 (LE) -> UTF-8.
std::string utf16_to_utf8(const char16_t* s, size_t n);
bool looks_like_text(const std::string& s);   // printable heuristic

} // namespace umvpqt
