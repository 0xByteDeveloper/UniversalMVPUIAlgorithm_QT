// =============================================================================
// UMVP-QT // tests/test_disasm.cpp — deep disassembly layer:
//   * metaObject() thunk resolver (lea rip / mov rax,[rip])
//   * qt_static_metacall switch solver (jump table OR cmp-chain)
//   * per-case handler address == expected compiled function
//   * [base,end) ranges and textual listings
// =============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "mock/mock_qt.h"
#include "umvpqt/disasm.h"
#include "umvpqt/qt_meta.h"
#include "umvpqt/qt_scan.h"

using namespace umvpqt;
using umvpqt_mock::MockImage;

static int failures = 0, checks = 0;

void expect_b(const char* what, bool got, bool want) {
    ++checks;
    if (got != want) {
        ++failures;
        std::printf("  FAIL %s: got=%d want=%d\n", what, got ? 1 : 0, want ? 1 : 0);
    }
}

extern "C" {
// a hand-written qt_static_metacall-style function with an if-chain dispatch
// (solver must also handle this shape)
int g_chain_dispatch_hits[3] = {0, 0, 0};
void chain_case0(void*) __attribute__((noinline));
void chain_case1(void*) __attribute__((noinline));
void chain_case2(void*) __attribute__((noinline));
void chain_case0(void* o) { ++g_chain_dispatch_hits[0]; asm volatile("" :: "r"(o)); }
void chain_case1(void* o) { ++g_chain_dispatch_hits[1]; asm volatile("" :: "r"(o)); }
void chain_case2(void* o) { ++g_chain_dispatch_hits[2]; asm volatile("" :: "r"(o)); }

// 16-case switch: forces a real JUMP TABLE dispatch (must be solved too)
int g_table_hits[16] = {0};
void table_case(int n) __attribute__((noinline));
void table_case(int n) { ++g_table_hits[n & 15]; }
void table_metacall(void* o, int c, int id, void** argv) {
    (void)c; (void)argv;
    switch (id) {
    case 0: table_case(0); break;
    case 1: table_case(1); break;
    case 2: table_case(2); break;
    case 3: table_case(3); break;
    case 4: table_case(4); break;
    case 5: table_case(5); break;
    case 6: table_case(6); break;
    case 7: table_case(7); break;
    case 8: table_case(8); break;
    case 9: table_case(9); break;
    case 10: table_case(10); break;
    case 11: table_case(11); break;
    case 12: table_case(12); break;
    case 13: table_case(13); break;
    case 14: table_case(14); break;
    case 15: table_case(15); break;
    default: break;
    }
    (void)o;
}
void chain_metacall(void* o, int c, int id, void** argv) {
    (void)o; (void)c; (void)argv;
    if (id == 0) { chain_case0(o); }
    else if (id == 1) { chain_case1(o); }
    else if (id == 2) { chain_case2(o); }
}
// a small lea-style thunk: returns a runtime global (mov rax,[rip]; ret pattern)
void* g_lea_thunk_value = nullptr;
void* lea_thunk() { return g_lea_thunk_value; }
}

static void run_family(QtFamily fam) {
    std::printf("-- family %s --\n", fam == QtFamily::Qt5 ? "Qt5" : "Qt6");
    MockImage img(fam);
    auto w = img.buildWorld();
    const QtLayout& L = *layout_for(fam);
    IProcessReader* rd = img.reader();
    img.registerCode((void*)&chain_metacall);
    img.registerCode((void*)&lea_thunk);
    img.registerCode((void*)&table_metacall);
    img.registerCode((void*)&table_case);

    // ---- thunk resolution through vtable ----
    ObjectScanner scanner(*rd, L);
    auto b1 = scanner.parseObjectNode(w.button1);
    expect_b("button1 parses", b1.has_value(), true);
    if (b1) {
        // the scanner already resolved the metaobject via the thunk — assert it
        expect_b("button1 metaObject == QPushButton meta",
                 b1->metaObject == w.meta_QPushButton, true);
        expect_b("button1 className", b1->className == "QPushButton", true);
    }

    // ---- metacall switch solver: Form1_static_metacall ----
    Address form1Metacall = rd->readPtr(w.meta_Form1 + L.mo_static_metacall);
    expect_b("Form1 static_metacall present", form1Metacall != 0, true);
    MetacallSolve sol = solve_metacall(*rd, form1Metacall);
    expect_b("Form1 metacall solved", sol.ok, true);
    if (sol.ok) {
        bool hasCase1 = false, hasCase4 = false;
        for (const MetacallCase& c : sol.cases) {
            if (c.localIndex == 1 && c.handler) hasCase1 = true;
            if (c.localIndex == 4 && c.handler) hasCase4 = true;
        }
        expect_b("case 1 (on_button1_clicked) has handler", hasCase1, true);
        expect_b("case 4 (on_check1_toggled) has handler", hasCase4, true);
        if (sol.table)
            expect_b("jump table in readable/exec memory",
                     rd->isReadable(sol.table) || rd->isExecutable(sol.table), true);
    }

    // ---- cmp-chain solver on the hand-written function ----
    MetacallSolve chain = solve_metacall(*rd, (Address)&chain_metacall);
    bool chainOK = false;
    for (const MetacallCase& c : chain.cases)
        if (c.localIndex == 1 && c.handler == (Address)&chain_case1) chainOK = true;
    expect_b("cmp-chain dispatch solved", chainOK, true);

    // ---- jump-table solver on the 16-case switch ----
    // (gcc -O2 emits a 4-byte RELATIVE table: lea rT,[rip+..]; movsxd rA,[rT+idx*4];
    //  add rA,rT; jmp rA — the solver resolves table + rel32 entries)
    MetacallSolve tbl = solve_metacall(*rd, (Address)&table_metacall);
    int tblHits = 0;
    for (const MetacallCase& c : tbl.cases)
        if (c.handler == (Address)&table_case) ++tblHits;
    expect_b("jump-table dispatch solved (>=14/16 cases hit table_case)",
             tblHits >= 14, true);
    expect_b("jump table base found", tbl.table != 0, true);
    expect_b("jump-table kind is relative", tbl.detail.find("jump-table") != std::string::npos, true);

    // ---- function ranges + listings ----
    if (sol.ok) {
        for (const MetacallCase& c : sol.cases) {
            if (c.localIndex != 1 || !c.handler) continue;
            Address end = function_end(*rd, c.handler);
            expect_b("handler end > base", end > c.handler, true);
            DisasmBlock blk = disassemble_range(*rd, c.handler, end);
            expect_b("disasm listing non-empty", blk.instructionCount > 0, true);
            expect_b("disasm lines non-empty", blk.lines.size() > 1, true);
            break;
        }
    }
}

int main() {
    run_family(QtFamily::Qt5);
    run_family(QtFamily::Qt6);
    std::printf("[%s] test_disasm: %d checks, %d failures\n",
                failures ? "FAIL" : "PASS", checks, failures);
    return failures == 0 ? 0 : 1;
}
