cmake_minimum_required(VERSION 3.28)

project(linuxauditmgr
    VERSION 0.1.0
    DESCRIPTION "Live, human-readable viewer for Linux audit logs"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Export compile_commands.json for clangd / IDE tooling.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})

set(warning_flags $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>)

# Non-GUI core (parsing + tailing), shared by the app and the tests.
add_library(auditcore STATIC
    src/AuditParser.cpp
    src/LogTailer.cpp
    src/AppArmorParser.cpp
    src/AppArmorDenials.cpp
    src/AppArmorEditor.cpp
    src/AppArmorValidator.cpp
    src/AppArmorNormalizer.cpp
)
target_include_directories(auditcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(auditcore PRIVATE ${warning_flags})
find_package(Threads REQUIRED)
target_link_libraries(auditcore PUBLIC Threads::Threads)

add_executable(linuxauditmgr
    src/App.cpp
    src/MainFrame.cpp
    src/AppArmorPanel.cpp
    src/AppArmorEventsPanel.cpp
    src/AppArmorValidationPanel.cpp
    src/AppArmorTab.cpp
)
target_link_libraries(linuxauditmgr PRIVATE auditcore ${wxWidgets_LIBRARIES})
target_compile_options(linuxauditmgr PRIVATE ${warning_flags})

# --- Installation -----------------------------------------------------------
# GNUInstallDirs provides the standard, prefix-relative directories
# (CMAKE_INSTALL_BINDIR, _DATADIR, _DOCDIR, …). The destinations honour
# CMAKE_INSTALL_PREFIX (default /usr/local) and DESTDIR for staged/packaged
# installs.
include(GNUInstallDirs)

install(TARGETS linuxauditmgr
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

# The desktop entry and the PolicyKit action embed the absolute path of the
# installed binary, so configure them from templates (@ONLY substitutes only
# @VAR@ placeholders). pkexec uses the action (matched by exec.path) to run the
# app as root for the desktop "Run as administrator" launch, retaining the GUI
# environment via the allow_gui annotation.
configure_file(linuxauditmgr.desktop.in linuxauditmgr.desktop @ONLY)
configure_file(org.radiotube.linuxauditmgr.policy.in
               org.radiotube.linuxauditmgr.policy @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/linuxauditmgr.desktop"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/org.radiotube.linuxauditmgr.policy"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/polkit-1/actions")

# Scalable app icon (referenced as Icon=linuxauditmgr by the desktop entry and
# the polkit action). The SVG covers every size on modern icon themes.
install(FILES linuxauditmgr.svg
    DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps")

install(FILES README.md
    DESTINATION "${CMAKE_INSTALL_DOCDIR}")

# Tests (Catch2). Enable with -DBUILD_TESTING=ON (default when top-level).
include(CTest)
if(BUILD_TESTING)
    find_package(Catch2 3 REQUIRED)
    add_executable(auditmgr_tests
        tests/test_parser.cpp
        tests/test_tailer.cpp
        tests/test_apparmor.cpp
        tests/test_apparmor_denials.cpp
        tests/test_apparmor_editor.cpp
        tests/test_apparmor_validator.cpp
        tests/test_apparmor_normalizer.cpp
    )
    target_link_libraries(auditmgr_tests PRIVATE auditcore Catch2::Catch2WithMain)
    target_compile_options(auditmgr_tests PRIVATE ${warning_flags})

    include(Catch)
    catch_discover_tests(auditmgr_tests)
endif()
