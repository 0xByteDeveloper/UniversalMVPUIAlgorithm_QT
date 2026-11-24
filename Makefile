# =============================================================================
# UMVP-QT // UniversalMVPUIAlgorithm_QT — Makefile
# GOD STATE build: layout DB regeneration + SDK + CLI + full independent tests.
# Dependencies: g++ (or clang++), make. Capstone optional (USE_CAPSTONE=1).
# =============================================================================
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wno-invalid-offsetof -Wno-unused-variable
INCLUDES  = -Iinclude -Isrc -Itools/gen_layout
BUILD    ?= build
BIN      ?= bin

SRC_CORE = src/qt_layout.cpp src/qt_meta.cpp src/qt_scan.cpp src/qt_signals.cpp \
           src/disasm.cpp src/qt_invoke.cpp src/analyzer.cpp src/report.cpp \
           src/process_common.cpp
ifeq ($(OS),Windows_NT)
SRC_CORE += src/process_win.cpp
LDLIBS   = -lole32 -lpsapi
else
SRC_CORE += src/process_posix.cpp
LDLIBS   =
endif

TESTS = test_layout test_metaobj test_disasm test_signals test_analyzer test_invoke

.PHONY: all tests cli gen clean run

all: gen cli tests

run: tests
	./$(BIN)/test_layout || echo test_layout FAILED
	./$(BIN)/test_metaobj || echo test_metaobj FAILED
	./$(BIN)/test_disasm || echo test_disasm FAILED
	./$(BIN)/test_signals || echo test_signals FAILED
	./$(BIN)/test_analyzer || echo test_analyzer FAILED
	./$(BIN)/test_invoke || echo test_invoke FAILED

# ---- layout DB (regenerate with offsetof from replica headers) ---------------
gen: $(BIN)/gen_layout src/qt_layout_db.h

$(BIN)/gen_layout: tools/gen_layout/gen_layout.cpp \
        tools/gen_layout/replica/qt5/qt_abi5.h tools/gen_layout/replica/qt6/qt_abi6.h
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) tools/gen_layout/gen_layout.cpp -o $@

src/qt_layout_db.h: $(BIN)/gen_layout
	$(BIN)/gen_layout > $@

# ---- static SDK ---------------------------------------------------------------
$(BUILD)/libumvpqt.a: $(SRC_CORE) src/qt_layout_db.h
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(SRC_CORE)
	ar rcs $@ $(notdir $(patsubst %.cpp,%.o,$(SRC_CORE)))
	@rm -f $(notdir $(patsubst %.cpp,%.o,$(SRC_CORE)))

# ---- CLI -----------------------------------------------------------------------
cli: $(BIN)/umvpqt_cli

$(BIN)/umvpqt_cli: cli/main.cpp $(BUILD)/libumvpqt.a
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) cli/main.cpp $(BUILD)/libumvpqt.a -o $@ $(LDLIBS)

# ---- demo (integration showcase) ----------------------------------------------
demo: $(BIN)/umvpqt_demo

$(BIN)/umvpqt_demo: tests/demo_main.cpp $(BUILD)/libumvpqt.a tests/mock/mock_qt.cpp tests/mock/mock_qt.h tests/mock/mock_executor.h src/qt_layout_db.h
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< tests/mock/mock_qt.cpp $(BUILD)/libumvpqt.a -o $@ $(LDLIBS)

# ---- independent tests ---------------------------------------------------------
tests: gen $(patsubst %,$(BIN)/%,$(TESTS))

$(BIN)/test_%: tests/test_%.cpp $(BUILD)/libumvpqt.a tests/mock/mock_qt.cpp tests/mock/mock_qt.h tests/mock/mock_executor.h src/qt_layout_db.h
	@mkdir -p $(BIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< tests/mock/mock_qt.cpp $(BUILD)/libumvpqt.a -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD) $(BIN) src/qt_layout_db.h
	rm -f *.o
