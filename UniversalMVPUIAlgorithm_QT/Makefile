# UMVPQT GOD STATE — Makefile (XPRO tarzi)
# ============================================================================
#  umvpqt_cli insaasi. Linux sandbox testleri icin QT5/QT6 hedefleri.
#  Uretim (Windows): mingw gecisi — QT hedef platformda normal derleme.
# ============================================================================

CXX      ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-invalid-offsetof
LDFLAGS  :=
CAPSTONE := -lcapstone

SRC := src/process_linux.cpp src/module.cpp src/qt_layouts.cpp src/qt_metaobject.cpp \
       src/qt_scan.cpp src/qt_connections.cpp src/qt_items.cpp src/disasm.cpp \
       src/analyzer.cpp src/report.cpp
INC := -Iinclude -Isrc

all: umvpqt_cli

umvpqt_cli: $(SRC) cli/main.cpp
        $(CXX) $(CXXFLAGS) $(INC) $(SRC) cli/main.cpp $(LDFLAGS) $(CAPSTONE) -o $@

# ---- test hedefleri (sandbox, QT kopyalari /home/z/my-project/toolchain altinda) ----
QTROOT ?= /home/z/my-project/toolchain/root

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

tests: umvpqt_cli demo_qt6 demo_qt5
        bash tests/run_integration.sh

clean:
        rm -f umvpqt_cli demo_qt6 demo_qt5 build_moc6.cpp build_moc5.cpp

.PHONY: all clean tests
