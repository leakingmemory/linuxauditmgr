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

add_executable(linuxauditmgr
    src/App.cpp
    src/MainFrame.cpp
    src/AuditParser.cpp
    src/LogTailer.cpp
)

target_link_libraries(linuxauditmgr PRIVATE ${wxWidgets_LIBRARIES})

target_compile_options(linuxauditmgr PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>
)
