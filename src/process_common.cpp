// =============================================================================
// UMVP-QT // src/process_common.cpp — IProcessReader region predicates
// (platform independent; used by every layer of the scanner).
// =============================================================================
#include "umvpqt/process.h"

namespace umvpqt {

namespace {
const MemoryRegion* find_region(const IProcessReader& r, Address a) {
    for (const MemoryRegion& reg : const_cast<IProcessReader&>(r).regions()) {
        if (a >= reg.start && a < reg.end) return &reg;
    }
    return nullptr;
}
} // namespace

bool IProcessReader::isReadable(Address a) const {
    if (!a) return false;
    const MemoryRegion* reg = find_region(*this, a);
    return reg && (reg->perms & 1);
}

bool IProcessReader::isWritable(Address a) const {
    if (!a) return false;
    const MemoryRegion* reg = find_region(*this, a);
    return reg && (reg->perms & 2);
}

bool IProcessReader::isExecutable(Address a) const {
    if (!a) return false;
    const MemoryRegion* reg = find_region(*this, a);
    return reg && (reg->perms & 4);
}

bool IProcessReader::inModule(Address a, const std::string& namePart) const {
    for (const ModuleInfo& m : const_cast<IProcessReader*>(this)->modules()) {
        if (m.base && a >= m.base && a < m.base + m.size &&
            m.name.find(namePart) != std::string::npos)
            return true;
    }
    return false;
}

} // namespace umvpqt
