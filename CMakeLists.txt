cmake_minimum_required(VERSION 3.14)
project(port_scanner VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# Port Scanner Library
# ============================================================

add_library(port_scanner SHARED port_scanner.cpp)

target_include_directories(port_scanner PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(port_scanner PRIVATE
        PORT_SCANNER_BUILD_DLL
        _WIN32_WINNT=0x0601
    )
    target_link_libraries(port_scanner ws2_32 iphlpapi)
elseif(ANDROID)
    # Android-specific settings
    target_compile_definitions(port_scanner PRIVATE
        ANDROID=1
    )
    target_link_libraries(port_scanner log)
elseif(APPLE)
    # macOS-specific settings
    target_compile_definitions(port_scanner PRIVATE
        __APPLE__=1
        __MACH__=1
    )
elseif(UNIX)
    # Linux and other Unix-like systems
    target_compile_definitions(port_scanner PRIVATE
        UNIX=1
        _GNU_SOURCE
    )
endif()

# Compiler warnings
target_compile_options(port_scanner PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Debug>:-g -O0>
    $<$<CONFIG:Release>:-O2 -DNDEBUG>
)

# Output names
set_target_properties(port_scanner PROPERTIES
    OUTPUT_NAME "port_scanner"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Platform-specific library suffix
if(WIN32)
    set_target_properties(port_scanner PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
    )
elseif(APPLE)
    set_target_properties(port_scanner PROPERTIES
        PREFIX "lib"
        SUFFIX ".dylib"
        MACOSX_RPATH ON
    )
else()
    set_target_properties(port_scanner PROPERTIES
        PREFIX "lib"
        SUFFIX ".so"
    )
endif()

# ============================================================
# CLI Executable
# ============================================================

add_executable(port_scanner_cli port_scanner_cli.cpp)
target_link_libraries(port_scanner_cli port_scanner)

if(WIN32)
    target_link_libraries(port_scanner_cli ws2_32)
endif()

# ============================================================
# Install targets
# ============================================================

install(TARGETS port_scanner
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES port_scanner.h
    DESTINATION include
)
