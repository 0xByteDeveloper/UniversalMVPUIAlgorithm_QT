# ============================================================================
#  UMVPQT GOD STATE — UniversalMVPUIAlgorithm_QT (CMake — Windows/Linux/macOS)
#  https://github.com/0xByteDeveloper/UniversalMVPUIAlgorithm_QT
#
#  Windows (uretim platformu):
#    cmake -B build -G "Visual Studio 17 2022" -A x64    (MSVC)
#    cmake -B build -G "MinGW Makefiles"                 (MinGW)
#    cmake --build build --config Release
#  Linux (sandbox test platformu):
#    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
#
#  Hedefler:
#    umvpqt_cli — pasif analiz CLI (tara + rapor + monitor + .asm)
#    uqt_agent  — YAPAY ZEKA surucu CLI (JSON-lines: bul + tikla + yaz + sec)
# ============================================================================
cmake_minimum_required(VERSION 3.12)
project(UniversalMVPUIAlgorithm_QT CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-invalid-offsetof)
endif()

# ---- Capstone (disassembly motoru) ----
# sistemde kuruluysa bulunur; yoksa ENV veya manuel yol verin:
#   -D CAPSTONE_ROOT=C:/capstone   (include + lib orada aranir)
set(CAPSTONE_ROOT "" CACHE PATH "Capstone kok dizini (opsiyonel)")
find_library(CAPSTONE_LIB NAMES capstone HINTS ${CAPSTONE_ROOT}/lib)
find_path(CAPSTONE_INC capstone/capstone.h HINTS ${CAPSTONE_INC} ${CAPSTONE_ROOT}/include)
if(NOT CAPSTONE_LIB)
    message(FATAL_ERROR "Capstone bulunamadi: cmake -DCAPSTONE_ROOT=... verin "
                        "(https://www.capstone-engine.org/download)")
endif()

set(UMVPQT_SOURCES
    src/module.cpp        src/qt_layouts.cpp    src/qt_metaobject.cpp
    src/qt_scan.cpp       src/qt_connections.cpp src/qt_items.cpp
    src/disasm.cpp        src/analyzer.cpp      src/report.cpp
    src/json.cpp          src/invoke_common.cpp src/agent.cpp
)

# ---- platform katmani ----
if(WIN32)
    list(APPEND UMVPQT_SOURCES src/process_win.cpp src/invoke_win.cpp)
else()
    list(APPEND UMVPQT_SOURCES src/process_linux.cpp src/invoke_linux.cpp)
endif()

include_directories(include src ${CAPSTONE_INC})

# ---- umvpqt_cli (pasif analiz) ----
add_executable(umvpqt_cli ${UMVPQT_SOURCES} cli/main.cpp)
target_link_libraries(umvpqt_cli ${CAPSTONE_LIB})
if(WIN32)
    target_link_libraries(umvpqt_cli psapi)   # Toolhelp32/Process mods
endif()

# ---- uqt_agent (yapay zeka surucu) ----
add_executable(uqt_agent ${UMVPQT_SOURCES} cli/agent_main.cpp)
target_link_libraries(uqt_agent ${CAPSTONE_LIB})
if(WIN32)
    target_link_libraries(uqt_agent psapi)
endif()

# ---- testler (yalniz Linux sandbox'ta: Qt5/Qt6 test hedefleri) ----
if(UNIX AND NOT APPLE)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    if(Qt6_FOUND)
        add_executable(vmprotect_mock tests/vmprotect_mock/vmprotect_mock.cpp)
        target_link_libraries(vmprotect_mock Qt6::Widgets)
        set_target_properties(vmprotect_mock PROPERTIES AUTOMOC ON)
    endif()
endif()

install(TARGETS umvpqt_cli uqt_agent RUNTIME DESTINATION bin)
