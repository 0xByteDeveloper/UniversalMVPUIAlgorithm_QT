# UMVPQT GOD STATE — Makefile (XPRO tarzi)
# ============================================================================
#  umvpqt_cli   : pasif analiz CLI (tara + rapor + monitor)
#  uqt_agent    : YAPAY ZEKA surucu CLI (JSON-lines: bul + TIKLA + yaz + sec)
#  demo_qt6/5   : sandbox test hedefleri
#  vmprotect_mock: VMProtect 3.9.4 is akisi mock'u (Qt6)
#  Uretim (Windows): CMakeLists.txt — MSVC/MinGW ile derlenir.
# ============================================================================

CXX      ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-invalid-offsetof
LDFLAGS  :=
CAPSTONE := -lcapstone

# sandbox toolchain (capstone/Qt) — Linux testler icin
QTROOT ?= /home/z/my-project/toolchain/root
SANDBOX_INC := -I$(QTROOT)/usr/include
SANDBOX_LIB := -L$(QTROOT)/usr/lib/x86_64-linux-gnu -Wl,-rpath,$(QTROOT)/usr/lib/x86_64-linux-gnu

SRC := src/process_linux.cpp src/module.cpp src/qt_layouts.cpp src/qt_metaobject.cpp \
	src/qt_scan.cpp src/qt_connections.cpp src/qt_items.cpp src/disasm.cpp \
	src/analyzer.cpp src/report.cpp
SRC += src/json.cpp src/invoke_common.cpp src/invoke_linux.cpp src/invoke_x11.cpp src/agent.cpp
INC := -Iinclude -Isrc $(SANDBOX_INC)

all: umvpqt_cli uqt_agent

umvpqt_cli: $(SRC) cli/main.cpp
	$(CXX) $(CXXFLAGS) $(INC) $(SRC) cli/main.cpp $(LDFLAGS) $(SANDBOX_LIB) $(CAPSTONE) -o $@

uqt_agent: $(SRC) cli/agent_main.cpp
	$(CXX) $(CXXFLAGS) $(INC) $(SRC) cli/agent_main.cpp $(LDFLAGS) $(SANDBOX_LIB) $(CAPSTONE) -o $@

# ---- test hedefleri (sandbox, QT kopyalari /home/z/my-project/toolchain altinda) ----

demo_qt6: tests/demo_target/demo_qt_app.cpp
	$(QTROOT)/usr/lib/qt6/libexec/moc tests/demo_target/demo_qt_app.cpp -o tests/demo_target/demo_qt_app_moc.inc
	$(CXX) -std=c++17 -fPIC tests/demo_target/demo_qt_app.cpp \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6 \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtCore \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtGui \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtWidgets \
	-Itests/demo_target \
	-L$(QTROOT)/usr/lib/x86_64-linux-gnu -Wl,-rpath-link,$(QTROOT)/usr/lib/x86_64-linux-gnu \
	-lQt6Widgets -lQt6Gui -lQt6Core -o $@

demo_qt5: tests/demo_target/demo_qt_app.cpp
	$(QTROOT)/usr/lib/qt5/bin/moc tests/demo_target/demo_qt_app.cpp -o tests/demo_target/demo_qt_app_moc.inc
	$(CXX) -std=c++17 -fPIC tests/demo_target/demo_qt_app.cpp \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt5 \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt5/QtCore \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt5/QtGui \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt5/QtWidgets \
	-Itests/demo_target \
	-L$(QTROOT)/usr/lib/x86_64-linux-gnu -Wl,-rpath-link,$(QTROOT)/usr/lib/x86_64-linux-gnu \
	-lQt5Widgets -lQt5Gui -lQt5Core -o $@

vmprotect_mock: tests/vmprotect_mock/vmprotect_mock.cpp
	$(QTROOT)/usr/lib/qt6/libexec/moc tests/vmprotect_mock/vmprotect_mock.cpp -o tests/vmprotect_mock/vmprotect_mock_moc.inc
	$(CXX) -std=c++17 -fPIC tests/vmprotect_mock/vmprotect_mock.cpp \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6 \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtCore \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtGui \
	-I$(QTROOT)/usr/include/x86_64-linux-gnu/qt6/QtWidgets \
	-Itests/vmprotect_mock \
	-L$(QTROOT)/usr/lib/x86_64-linux-gnu -Wl,-rpath-link,$(QTROOT)/usr/lib/x86_64-linux-gnu \
	-lQt6Widgets -lQt6Gui -lQt6Core -o $@

tests: umvpqt_cli uqt_agent demo_qt6 demo_qt5 vmprotect_mock
	bash tests/run_integration.sh
	bash tests/run_vmprotect_scenario.sh

clean:
	rm -f umvpqt_cli uqt_agent demo_qt6 demo_qt5 vmprotect_mock build_moc6.cpp build_moc5.cpp
	rm -f tests/demo_target/demo_qt_app_moc*.inc tests/vmprotect_mock/vmprotect_mock_moc.inc

.PHONY: all clean tests
