# UMVP-QT // UniversalMVPUIAlgorithm_QT — CMake convenience build
# (the canonical build is the Makefile; run `tools/gen_layout` first)
cmake_minimum_required(VERSION 3.16)
project(UniversalMVPUIAlgorithm_QT CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads)

add_executable(gen_layout tools/gen_layout/gen_layout.cpp)
target_include_directories(gen_layout PRIVATE include tools/gen_layout)
# generate src/qt_layout_db.h before building the SDK
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/qt_layout_db.h
    COMMAND gen_layout > ${CMAKE_SOURCE_DIR}/src/qt_layout_db.h
    DEPENDS gen_layout)
add_custom_target(gen_layout_db DEPENDS ${CMAKE_SOURCE_DIR}/src/qt_layout_db.h)

set(UMVP_SOURCES
    src/qt_layout.cpp src/qt_meta.cpp src/qt_scan.cpp src/qt_signals.cpp
    src/disasm.cpp src/qt_invoke.cpp src/analyzer.cpp src/report.cpp
    src/process_common.cpp)
if(WIN32)
    list(APPEND UMVP_SOURCES src/process_win.cpp)
else()
    list(APPEND UMVP_SOURCES src/process_posix.cpp)
endif()

add_library(umvpqt STATIC ${UMVP_SOURCES})
target_include_directories(umvpqt PUBLIC include src)
add_dependencies(umvpqt gen_layout_db)
target_link_libraries(umvpqt PUBLIC Threads::Threads)

add_executable(umvpqt_cli cli/main.cpp)
target_link_libraries(umvpqt_cli PRIVATE umvpqt)

enable_testing()
foreach(t layout metaobj disasm signals analyzer invoke)
    add_executable(test_${t} tests/test_${t}.cpp tests/mock/mock_qt.cpp)
    target_include_directories(test_${t} PRIVATE include src tools/gen_layout)
    target_link_libraries(test_${t} PRIVATE umvpqt)
    add_test(NAME test_${t} COMMAND test_${t})
endforeach()
add_executable(umvpqt_demo tests/demo_main.cpp tests/mock/mock_qt.cpp)
target_link_libraries(umvpqt_demo PRIVATE umvpqt)
