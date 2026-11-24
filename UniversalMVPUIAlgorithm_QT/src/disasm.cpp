// UMVPQT GOD STATE — Capstone Disassembly implementation
// ============================================================================
//  Itanium ABI: call rel32 = E8 xx; call [rip] = FF 15; mov rax,[rip] = 48 8B 05
//  Metacall: switch(_id) dongusu; her case -> slot cagrisi (call rel32).
// ============================================================================
#include "umvpqt/disasm.h"
#include <capstone/capstone.h>
#include <cstring>
#include <algorithm>

namespace umvpqt {

struct DisasmEngine::Impl {
    csh cs = 0;
    cs_insn* insn = nullptr;
};

bool DisasmEngine::init(IProcessReader& p, ModuleTable& m) {
    proc = &p;
    mt = &m;
    x86_64 = p.ptrSize() == 8;
    impl = new Impl;
    cs_mode mode = x86_64 ? (cs_mode)CS_MODE_64 : (cs_mode)CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &impl->cs) != CS_ERR_OK) return false;
    cs_option(impl->cs, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
}
DisasmEngine::~DisasmEngine() {
    if (impl) { if (impl->cs) cs_close(&impl->cs); delete impl; }
}

Addr DisasmEngine::resolveCallTarget(Addr callSite) {
    uint8_t b[8] = {};
    if (!proc->read(callSite, b, 8)) return 0;
    // call rel32: E8
    if (b[0] == 0xE8 && x86_64) {
        int32_t d = (int32_t)(b[1] | b[2] << 8 | b[3] << 16 | (uint32_t)b[4] << 24);
        return callSite + 5 + d;
    }
    if (b[0] == 0xE8) {   // 32-bit rel32
        int32_t d = (int32_t)(b[1] | b[2] << 8 | b[3] << 16 | (uint32_t)b[4] << 24);
        return callSite + 5 + d;
    }
    // call [rip+X]: FF 15 disp32
    if (x86_64 && b[0] == 0xFF && b[1] == 0x15) {
        int32_t d = (int32_t)(b[2] | b[3] << 8 | b[4] << 16 | (uint32_t)b[5] << 24);
        Addr slot = callSite + 6 + d;
        return proc->readAddr(slot);   // PLT/GOT cöz
    }
    // jmp rel32 (kuyruk cagrisi): E9
    if (b[0] == 0xE9) {
        int32_t d = (int32_t)(b[1] | b[2] << 8 | b[3] << 16 | (uint32_t)b[4] << 24);
        return callSite + 5 + d;
    }
    return 0;
}

std::map<int, Addr> DisasmEngine::parseMetacall(Addr fn, int methodCount) {
    std::map<int, Addr> out;
    if (!fn || !proc) return out;
    // metacall fonksiyonunu oku — ilk ret'te duracagiz (tek epilog varsayimi)
    size_t N = 0x2000;
    std::vector<uint8_t> code(N);
    if (!proc->read(fn, code.data(), N)) {
        N = 0x800;
        code.resize(N);
        if (!proc->read(fn, code.data(), N)) return out;
    }
    cs_insn* insns = nullptr;
    size_t total = cs_disasm(impl->cs, code.data(), code.size(), (uint64_t)fn, 4096, &insns);
    if (!total || !insns) return out;

    // ---- gecis 1: "cmp id,N" + "je hedef" ciftlerinden case govde haritasi ----
    std::map<Addr, int> caseAt;      // case govde adresi -> case no
    int lastCmp = -1;
    for (size_t i = 0; i < total; i++) {
        cs_insn& in = insns[i];
        if (strcmp(in.mnemonic, "ret") == 0) break;
        if (strncmp(in.mnemonic, "cmp", 3) == 0 && strstr(in.op_str, ",")) {
            int v = -1;
            const char* lastComma = strrchr(in.op_str, ',');
            if (sscanf(lastComma, ", %d", &v) == 1 || sscanf(lastComma, ", 0x%x", &v) == 1) {
                if (v >= 0 && v <= methodCount) lastCmp = v;
                else lastCmp = -1;
            }
        } else if ((strcmp(in.mnemonic, "je") == 0 || strcmp(in.mnemonic, "jz") == 0 ||
                    strcmp(in.mnemonic, "jne") == 0 || strcmp(in.mnemonic, "jnz") == 0) && lastCmp >= 0) {
            // hedef al: op_str "0x1234" (Intel) / "1234" 
            uint64_t tgt = strtoull(in.op_str, nullptr, 0);
            if (tgt > fn && tgt < fn + N) {
                caseAt[tgt] = lastCmp;
                lastCmp = -1;
            }
        } else {
            lastCmp = -1;   // cmp'ten baska sey araya girdi
        }
    }
    // ---- gecis 2: her case govdesindeki ILK call = slot fonksiyonu ----
    for (auto& [target, num] : caseAt) {
        // govdeyi bul (ayni disasm dizisinde)
        size_t startI = 0;
        for (size_t i = 0; i < total; i++)
            if (insns[i].address == target) { startI = i; break; }
        for (size_t i = startI; i < total && i < startI + 40; i++) {
            if (strcmp(insns[i].mnemonic, "ret") == 0) break;
            if (strncmp(insns[i].mnemonic, "call", 4) == 0) {
                size_t off = (size_t)(insns[i].address - fn);
                Addr t = 0;
                if (insns[i].size == 5 && off + 5 <= code.size() && code[off] == 0xE8) {
                    int32_t d = (int32_t)(code[off + 1] | code[off + 2] << 8 |
                                          code[off + 3] << 16 | (uint32_t)code[off + 4] << 24);
                    t = insns[i].address + 5 + d;
                } else if (insns[i].size == 6 && off + 6 <= code.size() &&
                           code[off] == 0xFF && code[off + 1] == 0x15 && x86_64) {
                    int32_t d = (int32_t)(code[off + 2] | code[off + 3] << 8 |
                                          code[off + 4] << 16 | (uint32_t)code[off + 5] << 24);
                    Addr slot = insns[i].address + 6 + d;
                    t = proc->readAddr(slot);
                } else {
                    t = resolveCallTarget(insns[i].address);
                }
                if (t && t > 0x10000 && out.find(num) == out.end()) out[num] = t;
                break;   // ilk call alindi
            }
        }
    }
    cs_free(insns, total);
    return out;
}

bool DisasmEngine::functionExtent(Addr start, Addr& end) {
    end = start + 0x200;   // her durumda bir sinir ver
    if (!mt) return false;
    const Symbol* s = mt->symbolAt(start);
    if (!s || s->address > start) return false;
    // sonraki sembol
    Addr next = 0;
    for (auto& m : mt->modules()) {
        for (auto& sy : m.symbols) {
            if (sy.address > start && (!next || sy.address < next)) {
                // ayni modulde olmali
                if (start >= m.base && start < m.end) next = sy.address;
            }
        }
    }
    if (next) {
        end = next;
        return true;
    }
    end = start + 0x200;   // fallback
    return false;
}

std::string DisasmEngine::disasmText(Addr start, Addr end, size_t maxInsn) {
    std::string out;
    if (end <= start || !proc) return out;
    size_t N = (size_t)(end - start);
    if (N > 0x4000) N = 0x4000;
    std::vector<uint8_t> code(N);
    if (!proc->read(start, code.data(), N)) return out;
    size_t want = maxInsn > 4096 ? 4096 : (maxInsn ? maxInsn : 1);
    cs_insn* insns = nullptr;
    size_t total = cs_disasm(impl->cs, code.data(), code.size(), (uint64_t)start, want, &insns);
    if (!total || !insns) return out;
    char buf[256];
    for (size_t i = 0; i < total; i++) {
        cs_insn& in = insns[i];
        snprintf(buf, sizeof(buf), "%12llx  %-8s %s\n",
                 (unsigned long long)in.address, in.mnemonic, in.op_str);
        out += buf;
        if (in.address + in.size >= end) break;
    }
    cs_free(insns, total);
    return out;
}

// ------------------------------------------------ VirtualSlotMap ---------
static Addr symbolAddress(const ModuleTable& mt, const std::string& name) {
    const Symbol* s = mt.findSymbolAny(name);
    return s ? s->address : 0;
}
static std::string itaniumMethod(const std::string& cls, const std::string& m) {
    return "_ZN" + std::to_string(cls.size()) + cls + std::to_string(m.size()) + m + "EP11QPaintEvent";
}

bool VirtualSlotMap::build(IProcessReader& proc, ModuleTable& mt, const std::string& baseClass) {
    this->proc = &proc;
    Addr vtSym = mt.vtableOf(baseClass);
    if (!vtSym) return false;
    Addr vt = vtSym + 2 * proc.ptrSize();   // offset-to-top + RTTI gec
    // QWidget::paintEvent sembolu: _ZN7QWidget10paintEventEP11QPaintEvent
    struct Want { const char* name; const char* mangled; } wants[] = {
        {"paintEvent",      "10paintEventEP11QPaintEvent"},
        {"mousePressEvent", "15mousePressEventEP11QMouseEvent"},
        {"mouseReleaseEvent","16mouseReleaseEventEP11QMouseEvent"},
        {"keyPressEvent",   "12keyPressEventEP9QKeyEvent"},
        {"resizeEvent",     "11resizeEventEP12QResizeEvent"},
        {"closeEvent",      "10closeEventEP11QCloseEvent"},
        {"wheelEvent",      "11wheelEventEP11QWheelEvent"},
    };
    for (auto& w : wants) {
        std::string sym = "_ZN" + std::to_string(baseClass.size()) + baseClass + w.mangled;
        Addr impl = symbolAddress(mt, sym);
        if (!impl) continue;
        // vtable'de indexini bul
        for (int idx = 0; idx < 200; idx++) {
            Addr entry = proc.readAddr(vt + (Addr)(idx * proc.ptrSize()));
            if (!entry || entry < 0x1000) break;
            if (entry == impl) {
                slots[w.name] = { idx, impl };
                break;
            }
        }
    }
    return !slots.empty();
}

Addr VirtualSlotMap::overridden(Addr vtable, const std::string& virtName) {
    auto it = slots.find(virtName);
    if (it == slots.end()) return 0;
    auto [idx, baseImpl] = it->second;
    // vtable parametresi zaten "vtable_ptr" (nesnede saklanan deger)
    Addr entry = 0;
    if (proc) entry = proc->readAddr(vtable + (Addr)(idx * proc->ptrSize()));
    if (!entry || entry == baseImpl) return 0;
    return entry;
}

} // namespace umvpqt
