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
)
target_include_directories(auditcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(auditcore PRIVATE ${warning_flags})
find_package(Threads REQUIRED)
target_link_libraries(auditcore PUBLIC Threads::Threads)

add_executable(linuxauditmgr
    src/App.cpp
    src/MainFrame.cpp
)
target_link_libraries(linuxauditmgr PRIVATE auditcore ${wxWidgets_LIBRARIES})
target_compile_options(linuxauditmgr PRIVATE ${warning_flags})

# Tests (Catch2). Enable with -DBUILD_TESTING=ON (default when top-level).
include(CTest)
if(BUILD_TESTING)
    find_package(Catch2 3 REQUIRED)
    add_executable(auditmgr_tests
        tests/test_parser.cpp
        tests/test_tailer.cpp
    )
    target_link_libraries(auditmgr_tests PRIVATE auditcore Catch2::Catch2WithMain)
    target_compile_options(auditmgr_tests PRIVATE ${warning_flags})

    include(Catch)
    catch_discover_tests(auditmgr_tests)
endif()
