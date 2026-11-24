// =============================================================================
// UMVP-QT // UniversalMVPUIAlgorithm_QT — include/umvpqt/disasm.h
// Deep disassembly layer:
//   * PatternDisasm  — self-contained x64 decoder for the instruction subset
//                     needed by the solver (no external deps; Capstone can be
//                     wired in behind the same API on machines that have it).
//   * resolveMetaObjectThunk — vtable slot 2 (metaObject()) -> staticMetaObject
//                     address, extracted from the thunk code (lea rax,[rip+..];ret
//                     / mov rax,imm64;ret).
//   * MetacallSolver — qt_static_metacall switch disassembly:
//                     jump-table [base, base+idx*scale] AND cmp-chain dispatch;
//                     per-case handler = first direct call target.
//   * functionEnd    — [base,end) range detection (ret + padding alignment).
// =============================================================================
#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "process.h"

namespace umvpqt {

enum class OpKind {
    Other,
    LeaRip,      // lea reg, [rip+disp]
    MovRipLoad,  // mov reg, [rip+disp]
    MovImm64,    // movabs reg, imm64
    MovImm32,    // mov e?reg, imm32
    CallRel,     // call rel32
    JmpRel,      // jmp rel32/rel8
    JmpMemSib,   // jmp qword ptr [reg + reg*scale]
    JmpMemRip,   // jmp qword ptr [rip+disp]
    JmpMemReg,   // jmp qword ptr [reg]
    JmpReg,      // jmp reg (indirect through register)
    JccRel,      // jcc rel
    CmpImm,      // cmp reg, imm (also test r,r -> ==0)
    SubImm,      // sub reg, imm
    Movsxd,      // movsxd reg, r32 / [base+idx*scale]
    AddRegs,    // add reg, reg
    Ret,
    Nop,
    Int3,
    Endbr64,
    PushPop
};

struct Insn {
    Address addr = 0;
    size_t size = 0;
    OpKind kind = OpKind::Other;
    int reg = -1;        // primary register (destination)
    int reg2 = -1;       // index register for SIB forms
    int base = -1;       // base register for SIB forms (-2 = rip)
    int scale = 0;       // 1/2/4/8
    uint64_t ripTarget = 0;  // rip-relative or rel target absolute address
    uint64_t imm = 0;
    std::string text;
};

class PatternDisasm {
public:
    // Decode as much as possible; unknown bytes become 1-byte "Other".
    static std::vector<Insn> decode(const uint8_t* code, size_t len, Address base);

    // Fetch code bytes through the reader and decode.
    static std::vector<Insn> decodeRange(IProcessReader& r, Address begin, size_t len);
};

// vtable[2] (metaObject thunk) -> static metaobject address. 0 on failure.
Address resolve_metaobject_thunk(IProcessReader& r, Address thunk);

// [base,end) estimation for a function entry (ret + padding).
Address function_end(IProcessReader& r, Address entry, size_t maxLen = 4096);

struct MetacallCase {
    int localIndex = 0;
    Address caseTarget = 0;    // switch-case entry
    Address handler = 0;      // first direct call target inside the case
    std::string kind;          // "jump-table" / "cmp-chain"
};

struct MetacallSolve {
    bool ok = false;
    Address function = 0;
    Address table = 0;               // jump table base (0 if cmp-chain)
    int tableEntries = 0;            // number of cases covered by the table
    int indexAdjust = 0;            // sub reg, imm before dispatch
    Address dispatchIndexReg = -1;  // register compared (as number)
    std::vector<MetacallCase> cases; // localIndex -> case target (+ handler)
    std::string detail;
};

// Disassemble qt_static_metacall / qt_metacall body and build the
// local-index -> handler map.
MetacallSolve solve_metacall(IProcessReader& r, Address fn, size_t scanLen = 512);

// Disassembly listing of [base,end) as text lines (addr  bytes  mnemonic).
DisasmBlock disassemble_range(IProcessReader& r, Address base, Address end, size_t maxInsn = 400);

} // namespace umvpqt
