// =============================================================================
// UMVP-QT // src/disasm.cpp — pattern decoder + metacall solver (x64, no PDB).
// Decodes the instruction subset emitted by GCC/Clang/MSVC for moc-generated
// qt_metacall / qt_static_metacall switches:
//     cmp   idx, N
//     ja    default
//     lea   rT, [rip+table]
//     (sub  idx, base)          ; optional case-range adjustment
//     jmp   qword ptr [rT + idx*8]
//  or cmp idx, K / je caseK (if-chain)
// case: ... call rel32 -> handler slot function
// Also decodes the metaObject() thunk:
//     lea rax, [rip+disp32]; ret      /     mov rax, imm64; ret
// =============================================================================
#include "umvpqt/disasm.h"

#include <cstring>
#include <cstdio>

namespace umvpqt {

namespace {

int reg64_of_rex_b(uint8_t rm, uint8_t rex) { return (rm & 7) | (rex & 1 ? 8 : 0); }

// scale factor encodings
int sib_scale(uint8_t sib) { return 1 << ((sib >> 6) & 3); }

std::string regname(int r) {
    static const char* names64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                      "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                      "r12", "r13", "r14", "r15"};
    if (r >= 0 && r < 16) return names64[r];
    return "?";
}

struct Reader {
    const uint8_t* c;
    size_t n;
    Address base;
    size_t i = 0;
    bool u8(uint8_t* v) { if (i >= n) return false; *v = c[i++]; return true; }
    bool u32(uint32_t* v) { if (i + 4 > n) return false; memcpy(v, c + i, 4); i += 4; return true; }
    bool u64(uint64_t* v) { if (i + 8 > n) return false; memcpy(v, c + i, 8); i += 8; return true; }
};

} // namespace

std::vector<Insn> PatternDisasm::decode(const uint8_t* code, size_t len, Address base) {
    std::vector<Insn> out;
    Reader rd{code, len, base};
    while (rd.i < len) {
        Insn in;
        in.addr = base + rd.i;
        size_t start = rd.i;
        uint8_t b0 = 0;
        if (!rd.u8(&b0)) break;

        uint8_t rex = 0;
        if (b0 >= 0x40 && b0 <= 0x4F) {
            rex = b0;
            if (!rd.u8(&b0)) break;
        } else if (b0 == 0xF3) {   // possible endbr64 (F3 0F 1E FA)
            uint8_t n1 = 0, n2 = 0, n3 = 0;
            size_t save = rd.i;
            if (rd.u8(&n1) && rd.u8(&n2) && rd.u8(&n3) && n1 == 0x0F && n2 == 0x1E && n3 == 0xFA) {
                in.kind = OpKind::Endbr64;
                in.size = rd.i - start;
                in.text = "endbr64";
                out.push_back(in);
                continue;
            }
            rd.i = save;   // unsupported F3-prefixed; treat as byte
            in.kind = OpKind::Other;
            in.size = 1;
            in.text = ".byte f3";
            out.push_back(in);
            continue;
        }

        auto finish = [&](OpKind k, const char* text) {
            in.kind = k;
            in.size = rd.i - start;
            in.text = text;
            out.push_back(in);
        };

        switch (b0) {
        case 0x90: finish(OpKind::Nop, "nop"); break;
        case 0xCC: finish(OpKind::Int3, "int3"); break;
        case 0xC3: finish(OpKind::Ret, "ret"); break;
        case 0xC2: {  // ret imm16 — consume exactly 2 bytes (STACK-SAFE)
            uint8_t lo = 0, hi = 0;
            rd.u8(&lo);
            rd.u8(&hi);
            (void)lo; (void)hi;
            finish(OpKind::Ret, "ret imm16");
            break;
        }
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            finish(OpKind::PushPop, ((b0 & 0xF8) == 0x50) ? "push" : "pop");
            break;
        case 0xE8: {  // call rel32
            uint32_t d = 0;
            if (rd.u32(&d)) {
                in.kind = OpKind::CallRel;
                in.ripTarget = in.addr + (rd.i - start) + (int32_t)d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "call 0x%llx", (unsigned long long)in.ripTarget);
                in.text = buf;
            } else in.text = "call ?";
            in.size = rd.i - start;
            out.push_back(in);
            break;
        }
        case 0xE9: {  // jmp rel32
            uint32_t d = 0;
            if (rd.u32(&d)) {
                in.kind = OpKind::JmpRel;
                in.ripTarget = in.addr + (rd.i - start) + (int32_t)d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "jmp 0x%llx", (unsigned long long)in.ripTarget);
                in.text = buf;
            } else in.text = "jmp ?";
            in.size = rd.i - start;
            out.push_back(in);
            break;
        }
        case 0xEB: {  // jmp rel8
            uint8_t d = 0;
            if (rd.u8(&d)) {
                in.kind = OpKind::JmpRel;
                in.ripTarget = in.addr + (rd.i - start) + (int8_t)d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "jmp 0x%llx", (unsigned long long)in.ripTarget);
                in.text = buf;
            }
            in.size = rd.i - start;
            out.push_back(in);
            break;
        }
        case 0x0F: {  // two-byte opcodes
            uint8_t op = 0;
            if (!rd.u8(&op)) { in.size = rd.i - start; in.text = "0f?"; out.push_back(in); break; }
            if (op >= 0x80 && op <= 0x8F) {   // jcc rel32
                uint32_t d = 0;
                rd.u32(&d);
                in.kind = OpKind::JccRel;
                in.ripTarget = in.addr + (rd.i - start) + (int32_t)d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "jcc 0x%llx", (unsigned long long)in.ripTarget);
                in.text = buf;
            } else if (op == 0x1F) {          // nop /r (multi-byte)
                uint8_t rm = 0;
                rd.u8(&rm);
                in.kind = OpKind::Nop;
                in.text = "nop";
            } else if (op == 0x05) {          // syscall
                in.text = "syscall";
            } else {
                in.text = "0f..";
            }
            in.size = rd.i - start;
            out.push_back(in);
            break;
        }
        case 0x48: case 0x49: {  // (with rex consumed above, these arrive as b0 after rex)
            // unreachable when REX handled above; keep safe
            in.size = 1; in.text = "?"; out.push_back(in);
            break;
        }
        default: {
            if ((b0 >= 0x70 && b0 <= 0x7F) && rex == 0) {   // jcc rel8
                uint8_t d = 0;
                rd.u8(&d);
                in.kind = OpKind::JccRel;
                in.ripTarget = in.addr + (rd.i - start) + (int8_t)d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "jcc 0x%llx", (unsigned long long)in.ripTarget);
                in.text = buf;
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x8D && rex) {  // lea r64, [..]
                uint8_t modrm = 0;
                if (!rd.u8(&modrm)) break;
                int mod = modrm >> 6, reg = ((modrm >> 3) & 7) | ((rex >> 2) & 4), rm = modrm & 7;
                if (mod == 0 && rm == 5) {   // rip-relative
                    uint32_t d = 0;
                    rd.u32(&d);
                    in.reg = reg;
                    in.kind = OpKind::LeaRip;
                    in.ripTarget = in.addr + (rd.i - start + 4) + (int32_t)d;
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "lea %s, [rip+0x%x] ; =0x%llx",
                                  regname(reg).c_str(), d, (unsigned long long)in.ripTarget);
                    in.text = buf;
                } else if (mod == 0 && rm == 4) {  // SIB
                    uint8_t sib = 0;
                    rd.u8(&sib);
                    in.reg = reg;
                    in.kind = OpKind::Other;
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "lea %s, [%s+%s*%d]",
                                  regname(reg).c_str(),
                                  regname(sib & 7).c_str(), regname((sib >> 3) & 7).c_str(),
                                  sib_scale(sib));
                    in.text = buf;
                } else {
                    // lea reg,[reg+disp] etc — plain text
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "lea %s, [r%d%+d]",
                                  regname(reg).c_str(), rm, mod == 1 ? 8 : mod == 2 ? 32 : 0);
                    in.text = buf;
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x8B && rex) {  // mov r64, r/m64
                uint8_t modrm = 0;
                if (!rd.u8(&modrm)) break;
                int mod = modrm >> 6, reg = ((modrm >> 3) & 7) | ((rex >> 2) & 4),
                    rm = reg64_of_rex_b(modrm & 7, rex);
                if (mod == 0 && rm == 5) {
                    uint32_t d = 0;
                    rd.u32(&d);
                    in.kind = OpKind::MovRipLoad;
                    in.reg = reg;
                    in.ripTarget = in.addr + (rd.i - start + 4) + (int32_t)d;
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "mov %s, [rip+0x%x] ; =0x%llx",
                                  regname(reg).c_str(), d, (unsigned long long)in.ripTarget);
                    in.text = buf;
                } else if (mod == 0 && (modrm & 7) == 4) {  // SIB [base+idx*scale]
                    uint8_t sib = 0;
                    rd.u8(&sib);
                    in.reg = reg;
                    in.reg2 = (sib >> 3) & 15;
                    in.scale = sib_scale(sib);
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "mov %s, [%s+%s*%d]",
                                  regname(reg).c_str(), regname(sib & 7).c_str(),
                                  regname(in.reg2).c_str(), in.scale);
                    in.text = buf;
                } else if (mod == 0) {
                    in.reg = reg;
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "mov %s, [%s]", regname(reg).c_str(), regname(rm));
                    in.text = buf;
                } else {
                    in.reg = reg;
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "mov %s, [r%d%+d]", regname(reg).c_str(), rm,
                                  mod == 1 ? 8 : 32);
                    in.text = buf;
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0xFF) {  // jmp/call /2 /4 with modrm
                uint8_t modrm = 0;
                if (!rd.u8(&modrm)) break;
                int mod = modrm >> 6, op2 = (modrm >> 3) & 7, rm = modrm & 7;
                if (op2 == 4 || op2 == 2) {   // jmp/call r/m
                    if (mod == 0 && rm == 5) {  // [rip+disp]
                        uint32_t d = 0;
                        rd.u32(&d);
                        in.kind = op2 == 4 ? OpKind::JmpMemRip : OpKind::Other;
                        in.ripTarget = in.addr + (rd.i - start + 4) + (int32_t)d;
                        char buf[64];
                        std::snprintf(buf, sizeof buf, "%s qword ptr [rip+0x%x] ; =0x%llx",
                                      op2 == 4 ? "jmp" : "call", d,
                                      (unsigned long long)in.ripTarget);
                        in.text = buf;
                    } else if (mod == 0 && rm == 4) {  // SIB
                        uint8_t sib = 0;
                        rd.u8(&sib);
                        in.kind = op2 == 4 ? OpKind::JmpMemSib : OpKind::Other;
                        in.reg = sib & 15;                    // base register
                        in.reg2 = ((sib >> 3) & 15);
                        in.scale = sib_scale(sib);
                        char buf[64];
                        std::snprintf(buf, sizeof buf, "%s qword ptr [%s+%s*%d]",
                                      op2 == 4 ? "jmp" : "call",
                                      regname(in.reg).c_str(), regname(in.reg2).c_str(), in.scale);
                        in.text = buf;
                    } else if (mod == 0) {
                        in.kind = op2 == 4 ? OpKind::JmpMemReg : OpKind::Other;
                        in.reg = rm;
                        char buf[48];
                        std::snprintf(buf, sizeof buf, "%s qword ptr [%s]",
                                      op2 == 4 ? "jmp" : "call", regname(rm));
                        in.text = buf;
                    } else if (mod == 3) {  // jmp/call reg
                        in.kind = op2 == 4 ? OpKind::JmpReg : OpKind::Other;
                        in.reg = reg64_of_rex_b(modrm & 7, rex);
                        char buf[40];
                        std::snprintf(buf, sizeof buf, "%s %s",
                                      op2 == 4 ? "jmp" : "call", regname(in.reg).c_str());
                        in.text = buf;
                    } else {
                        in.text = "ff /r";
                        if (mod == 1) { uint8_t _; rd.u8(&_); }
                        else if (mod == 2) { uint32_t _; rd.u32(&_); }
                    }
                } else {
                    in.text = "ff..";
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if ((b0 == 0xB8 + (b0 & 7)) && (b0 >= 0xB8 && b0 <= 0xBF)) {  // mov e?reg, imm32
                uint32_t d = 0;
                rd.u32(&d);
                in.kind = OpKind::MovImm32;
                in.reg = b0 & 7;
                in.imm = d;
                char buf[64];
                std::snprintf(buf, sizeof buf, "mov e%s, 0x%x", regname(b0 & 7).c_str() + 1, d);
                in.text = buf;
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x81 || b0 == 0x83) {  // cmp/sub/add r/m, imm (opcode /digit)
                uint8_t modrm = 0;
                if (!rd.u8(&modrm)) break;
                int mod = modrm >> 6, digit = (modrm >> 3) & 7, rm = modrm & 7;
                uint32_t imm = 0;
                if (b0 == 0x81) rd.u32(&imm); else { uint8_t i8; rd.u8(&i8); imm = i8; }
                if (mod == 1) { uint8_t _; rd.u8(&_); }
                if (mod == 2) { uint32_t _; rd.u32(&_); }
                in.reg = rm;
                in.imm = imm;
                if (digit == 7) {
                    in.kind = OpKind::CmpImm;
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "cmp r%d, 0x%llx", rm, (unsigned long long)imm);
                    in.text = buf;
                } else if (digit == 5) {
                    in.kind = OpKind::SubImm;
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "sub r%d, 0x%llx", rm, (unsigned long long)imm);
                    in.text = buf;
                } else {
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "arith r%d, 0x%llx", rm, (unsigned long long)imm);
                    in.text = buf;
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x89 || b0 == 0x8B) {  // mov r,r / r<-r
                uint8_t modrm = 0;
                if (!rd.u8(&modrm)) break;
                int mod = modrm >> 6;
                if (mod == 3) {
                    in.reg = ((modrm >> 3) & 7) | ((rex >> 2) & 4);
                    in.reg2 = reg64_of_rex_b(modrm & 7, rex);
                    char buf[48];
                    if (b0 == 0x89)
                        std::snprintf(buf, sizeof buf, "mov %s, %s", regname(in.reg2).c_str(),
                                      regname(in.reg).c_str());
                    else
                        std::snprintf(buf, sizeof buf, "mov %s, %s", regname(in.reg).c_str(),
                                      regname(in.reg2).c_str());
                    in.text = buf;
                } else {
                    in.text = "mov r,m";
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                    else if (mod == 0 && (modrm & 7) == 4) { uint8_t _; rd.u8(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x63 && rex) {  // movsxd reg, r/m32
                uint8_t modrm = 0;
                rd.u8(&modrm);
                int mod = modrm >> 6;
                in.reg = ((modrm >> 3) & 7) | ((rex >> 2) & 4);
                in.kind = OpKind::Movsxd;
                if (mod == 0 && (modrm & 7) == 4) {          // SIB [base+idx*scale]
                    uint8_t sib = 0;
                    rd.u8(&sib);
                    in.reg2 = (sib >> 3) & 15;               // index
                    in.scale = sib_scale(sib);
                    in.base = sib & 15;                      // base
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "movsxd %s, [%s+%s*%d]",
                                   regname(in.reg).c_str(), regname(in.base).c_str(),
                                   regname(in.reg2).c_str(), in.scale);
                    in.text = buf;
                } else if (mod == 0 && (modrm & 7) == 5) {   // [rip+disp32]
                    uint32_t d = 0;
                    rd.u32(&d);
                    in.base = -2;                            // rip
                    char buf[64];
                    std::snprintf(buf, sizeof buf, "movsxd %s, [rip+0x%x]",
                                   regname(in.reg).c_str(), d);
                    in.text = buf;
                } else if (mod == 3) {
                    in.reg2 = reg64_of_rex_b(modrm & 7, rex);
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "movsxd %s, e%s", regname(in.reg).c_str(),
                                  regname(in.reg2).c_str() + 1);
                    in.text = buf;
                } else {
                    in.text = "movsxd rm";
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x01 && rex) {  // add r64, r64 (48 01 /r)
                uint8_t modrm = 0;
                rd.u8(&modrm);
                int mod = modrm >> 6;
                if (mod == 3) {
                    in.kind = OpKind::AddRegs;
                    in.reg = reg64_of_rex_b(modrm & 7, rex);          // dest (r/m)
                    in.reg2 = ((modrm >> 3) & 7) | ((rex >> 2) & 4); // src
                    char buf[48];
                    std::snprintf(buf, sizeof buf, "add %s, %s", regname(in.reg).c_str(),
                                  regname(in.reg2).c_str());
                    in.text = buf;
                } else {
                    in.text = "add rm";
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                    else if (mod == 0 && (modrm & 7) == 4) { uint8_t _; rd.u8(&_); }
                    else if (mod == 0 && (modrm & 7) == 5) { uint32_t _; rd.u32(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x31 || b0 == 0x33) {  // xor
                uint8_t modrm = 0;
                rd.u8(&modrm);
                in.text = "xor";
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0x85) {  // test r,r -> cmp reg, 0 (id==0 chains)
                uint8_t modrm = 0;
                rd.u8(&modrm);
                int mod = modrm >> 6;
                if (mod == 3) {
                    in.kind = OpKind::CmpImm;
                    in.reg = reg64_of_rex_b(modrm & 7, rex);
                    in.imm = 0;
                    char buf[40];
                    std::snprintf(buf, sizeof buf, "test %s,%s",
                                  regname(((modrm >> 3) & 7) | ((rex >> 2) & 4)).c_str(),
                                  regname(in.reg).c_str());
                    in.text = buf;
                } else {
                    in.text = "test rm";
                    if (mod == 1) { uint8_t _; rd.u8(&_); }
                    else if (mod == 2) { uint32_t _; rd.u32(&_); }
                }
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            if (b0 == 0xC7) {  // mov r/m, imm32
                uint8_t modrm = 0;
                rd.u8(&modrm);
                uint32_t imm = 0;
                rd.u32(&imm);
                in.text = "mov rm, imm";
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            // movabs reg, imm64 (REX.W + B8+r)
            if (rex && (rex & 8) && b0 >= 0xB8 && b0 <= 0xBF) {
                uint64_t imm = 0;
                rd.u64(&imm);
                in.kind = OpKind::MovImm64;
                in.reg = (b0 & 7) | ((rex & 1) ? 8 : 0);
                in.imm = imm;
                char buf[64];
                std::snprintf(buf, sizeof buf, "movabs %s, 0x%llx", regname(in.reg).c_str(),
                              (unsigned long long)imm);
                in.text = buf;
                in.size = rd.i - start;
                out.push_back(in);
                break;
            }
            // fallthrough: unknown byte
            in.kind = OpKind::Other;
            in.size = 1;
            in.text = ".byte";
            out.push_back(in);
            break;
        }
        }
        if (rd.i == start) {   // safety: never loop forever
            Insn bad;
            bad.addr = base + rd.i;
            bad.size = 1;
            bad.kind = OpKind::Other;
            bad.text = ".byte stall";
            out.push_back(bad);
            ++rd.i;
        }
    }
    return out;
}

std::vector<Insn> PatternDisasm::decodeRange(IProcessReader& r, Address begin, size_t len) {
    if (len > (1 << 20)) len = 1 << 20;   // hard cap (safety)
    std::vector<uint8_t> buf(len);
    if (!r.read(begin, buf.data(), len)) {
        // partial read fallback
        for (size_t i = 0; i < len; ++i)
            if (!r.read(begin + i, &buf[i], 1)) buf[i] = 0xCC;
    }
    return decode(buf.data(), len, begin);
}

Address resolve_metaobject_thunk(IProcessReader& r, Address thunk) {
    uint8_t code[48] = {0};
    if (!r.read(thunk, code, sizeof code)) return 0;
    // helper: is there a `ret` (C3) within [pos, pos+8) (allow pop rbp `5d`,
    // pop rbx etc. epilogues)?
    auto retSoon = [&](size_t pos) -> bool {
        for (size_t k = pos; k < pos + 8 && k < sizeof code; ++k)
            if (code[k] == 0xC3) return true;
        return false;
    };
    for (size_t i = 0; i + 8 < sizeof code; ++i) {
        // Pattern A: lea rax,[rip+disp32] ... ret
        if (code[i] == 0x48 && code[i + 1] == 0x8D && (code[i + 2] & 0xC7) == 0x05) {
            int32_t disp;
            memcpy(&disp, code + i + 3, 4);
            if (retSoon(i + 7))
                return thunk + i + 7 + disp;
        }
        // Pattern B: movabs r64, imm64 ... ret
        if (code[i] == 0x48 && code[i + 1] >= 0xB8 && code[i + 1] <= 0xBF) {
            uint64_t imm;
            memcpy(&imm, code + i + 2, 8);
            if (retSoon(i + 10))
                return (Address)imm;
        }
        // Pattern C (MSVC): mov e?ax, imm32 ... ret
        if (code[i] >= 0xB8 && code[i] <= 0xBF && i > 0 && code[i-1] != 0x48) {
            uint32_t imm;
            memcpy(&imm, code + i + 1, 4);
            if (retSoon(i + 5))
                return (Address)imm;
        }
        // Pattern D (PIC): mov rax, [rip+disp32] ... ret  -> *(&global)
        if (code[i] == 0x48 && code[i + 1] == 0x8B && (code[i + 2] & 0xC7) == 0x05) {
            int32_t disp;
            memcpy(&disp, code + i + 3, 4);
            if (retSoon(i + 7)) {
                Address global = thunk + i + 7 + disp;
                uint64_t mo = 0;
                if (r.read(global, &mo, 8)) return (Address)mo;
            }
        }
    }
    return 0;
}

Address function_end(IProcessReader& r, Address entry, size_t maxLen) {
    auto insns = PatternDisasm::decodeRange(r, entry, maxLen);
    Address lastRet = 0;
    for (auto& in : insns) {
        if (in.kind == OpKind::Ret) {
            lastRet = in.addr + in.size;
            // ret + trailing nop/int3/zero padding up to next boundary
            Address p = lastRet;
            uint8_t b = 0;
            for (Address a = lastRet; a - entry < maxLen; ++a) {
                if (!r.read(a, &b, 1)) break;
                if (b == 0x90 || b == 0xCC || b == 0x00) { ++p; continue; }
                break;
            }
            return p;
        }
    }
    return lastRet ? lastRet : entry + maxLen;
}

MetacallSolve solve_metacall(IProcessReader& r, Address fn, size_t scanLen) {
    MetacallSolve res;
    res.function = fn;
    auto ins = PatternDisasm::decodeRange(r, fn, scanLen);
    if (ins.empty()) { res.detail = "no code"; return res; }

    auto callTargetInside = [&](Address caseStart) -> Address {
        // first direct call rel32 within the case block; a LEADING jmp rel32 is a
        // tail-call to the handler; stop at ret/jmp.
        auto cins = PatternDisasm::decodeRange(r, caseStart, 96);
        for (auto& ci : cins) {
            if (ci.kind == OpKind::CallRel && ci.ripTarget) return ci.ripTarget;
            if (ci.kind == OpKind::JmpRel && ci.ripTarget) return ci.ripTarget;
            if (ci.kind == OpKind::Ret) break;
        }
        return 0;
    };
    auto handlerFor = [&](Address caseStart) -> Address {
        // preferred: the direct call target (real slot body);
        // fallback: the case body itself (slot INLINED into the metacall).
        Address call = callTargetInside(caseStart);
        return call ? call : caseStart;
    };

    // ---- pass 1: locate dispatch ------------------------------------------------
    // direct jump-table form:
    //   cmp reg, N ; jcc default ; lea rT,[rip+X] ; (sub reg,K)? ; jmp [rT+reg*8]
    // relative jump-table form (gcc -fPIE):
    //   cmp reg, N ; jcc default ; lea rT,[rip+X] ; movsxd rA,[rT+reg*4] ;
    //   add rA, rT ; jmp rA              (4-byte RELATIVE table entries)
    // cmp-chain form:
    //   cmp reg, K ; jcc caseK ; ...  (multiple pairs; test r,r == cmp 0)
    int indexReg = -1;
    int cmpBound = -1;
    Address table = 0;
    int indexAdjust = 0;
    bool sawSub = false;
    std::vector<std::pair<uint64_t, Address>> cmpPairs;   // imm -> target

    Address lastLeaRegTable[16] = {0};
    // relative-table tracking
    Address relTable = 0;
    int relIdx = -1, relScale = 4, relDst = -1;
    bool relReady = false;

    for (size_t i = 0; i < ins.size(); ++i) {
        const Insn& in = ins[i];
        switch (in.kind) {
        case OpKind::LeaRip:
            if (in.reg >= 0 && in.reg < 16) lastLeaRegTable[in.reg] = in.ripTarget;
            break;
        case OpKind::SubImm:
            if (in.reg >= 0) { indexAdjust = (int)in.imm; sawSub = true; }
            break;
        case OpKind::CmpImm: {
            indexReg = in.reg;
            if (cmpBound < 0) cmpBound = (int)in.imm;
            // chain: look ahead for jcc
            if (i + 1 < ins.size() && ins[i + 1].kind == OpKind::JccRel) {
                cmpPairs.emplace_back(in.imm, ins[i + 1].ripTarget);
                // immediate next: possibly another cmp/jcc pair
                if (i + 3 < ins.size() && ins[i + 2].kind == OpKind::CmpImm &&
                    ins[i + 3].kind == OpKind::JccRel) {
                    cmpPairs.emplace_back(ins[i + 2].imm, ins[i + 3].ripTarget);
                    i += 3;
                } else {
                    i += 1;
                }
            }
            break;
        }
        case OpKind::Movsxd: {
            // movsxd rA, [rT + idx*scale] with rT holding a lea'd table
            if (in.reg >= 0 && in.reg2 >= 0 && in.base >= 0 && in.base < 16 &&
                lastLeaRegTable[in.base]) {
                relTable = lastLeaRegTable[in.base];
                relIdx = in.reg2;
                relScale = in.scale ? in.scale : 4;
                relDst = in.reg;
                relReady = false;
            }
            break;
        }
        case OpKind::AddRegs: {
            // add rA, rT  -> rA now holds table + rel32 entry
            if (relDst == in.reg && in.reg2 >= 0 && in.reg2 < 16 &&
                lastLeaRegTable[in.reg2] == relTable && relTable)
                relReady = true;
            break;
        }
        case OpKind::JmpReg: {
            // jmp rA with rA = table + rel32 -> relative jump table dispatch
            if (relReady && in.reg == relDst && relTable) {
                int n = cmpBound + 1;
                if (n > 0 && n <= 512) {
                    for (int k = 0; k < n; ++k) {
                        uint32_t rel = 0;
                        if (!r.readU32(relTable + (Address)k * relScale, &rel)) break;
                        Address target = relTable + (int64_t)(int32_t)rel;
                        if (!r.isExecutable(target)) continue;
                        MetacallCase c;
                        c.localIndex = k + (sawSub ? indexAdjust : 0);
                        c.caseTarget = target;
                        c.handler = handlerFor(target);
                        c.kind = "jump-table-rel32";
                        res.cases.push_back(c);
                    }
                    if (!res.cases.empty()) {
                        res.ok = true;
                        res.table = relTable;
                        res.tableEntries = n;
                        res.indexAdjust = sawSub ? indexAdjust : 0;
                        res.dispatchIndexReg = relIdx;
                        res.detail = "relative jump-table dispatch (gcc PIE)";
                        return res;
                    }
                }
            }
            break;
        }
        case OpKind::JmpMemSib: {
            // jmp qword ptr [base + idx*scale]
            if (in.reg >= 0 && in.reg < 16 && in.reg2 >= 0 && in.reg2 < 16 &&
                in.scale == 8 && in.reg2 == indexReg) {
                table = lastLeaRegTable[in.reg];
            }
            break;
        }
        case OpKind::JmpMemRip:
            // jmp qword ptr [rip+X] — rare table-indirect; treat table = target
            table = 0;   // not a table base; ignore
            break;
        default: break;
        }
    }

    // ---- pass 2: build cases -----------------------------------------------------
    if (table && r.isExecutable(table)) {
        int n = cmpBound + 1;   // cmp idx, N ; ja -> cases 0..N
        if (n > 0 && n <= 512) {
            for (int k = 0; k < n; ++k) {
                uint64_t entry = 0;
                if (!r.readU64(table + (Address)k * 8, &entry)) break;
                if (!r.isExecutable((Address)entry)) continue;
                MetacallCase c;
                c.localIndex = k + (sawSub ? indexAdjust : 0);
                c.caseTarget = (Address)entry;
                c.handler = handlerFor(c.caseTarget);
                c.kind = "jump-table";
                res.cases.push_back(c);
            }
            if (!res.cases.empty()) {
                res.ok = true;
                res.table = table;
                res.tableEntries = n;
                res.indexAdjust = sawSub ? indexAdjust : 0;
                res.dispatchIndexReg = indexReg;
                res.detail = "jump-table dispatch";
            }
        }
    }
    if (!res.ok && !cmpPairs.empty()) {
        for (auto& [imm, target] : cmpPairs) {
            if (!r.isExecutable(target)) continue;
            MetacallCase c;
            c.localIndex = (int)imm;
            c.caseTarget = target;
            c.handler = handlerFor(target);
            c.kind = "cmp-chain";
            res.cases.push_back(c);
        }
        if (!res.cases.empty()) {
            res.ok = true;
            res.detail = "cmp-chain dispatch";
        }
    }
    if (!res.ok) res.detail = "dispatch pattern not found";
    return res;
}

DisasmBlock disassemble_range(IProcessReader& r, Address base, Address end, size_t maxInsn) {
    DisasmBlock blk;
    blk.base = base;
    blk.end = end;
    if (end <= base) return blk;
    size_t len = (size_t)(end - base);
    if (len > 65536) len = 65536;
    auto ins = PatternDisasm::decodeRange(r, base, len);
    char header[64];
    std::snprintf(header, sizeof header, "; [0x%llx .. 0x%llx)",
                  (unsigned long long)base, (unsigned long long)end);
    blk.lines.emplace_back(header);
    for (auto& in : ins) {
        if (blk.lines.size() >= maxInsn + 1) {
            blk.lines.emplace_back("; ... (truncated)");
            break;
        }
        std::string line;
        char addr[32];
        std::snprintf(addr, sizeof addr, "0x%016llx  ", (unsigned long long)in.addr);
        line += addr;
        // bytes
        uint8_t raw[16] = {0};
        r.read(in.addr, raw, in.size > 16 ? 16 : in.size);
        char hex[3];
        for (size_t b = 0; b < in.size && b < 16; ++b) {
            std::snprintf(hex, sizeof hex, "%02x", raw[b]);
            line += hex;
            line += ' ';
        }
        for (size_t pad = in.size; pad < 12; ++pad) line += "   ";
        line += in.text;
        blk.lines.push_back(line);
        ++blk.instructionCount;
    }
    return blk;
}

} // namespace umvpqt
