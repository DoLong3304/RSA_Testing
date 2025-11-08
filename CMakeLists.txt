cmake_minimum_required(VERSION 4.0)
project(RSA C)

set(CMAKE_C_STANDARD 17)

add_executable(RSA main.c
        rsa.h
        rsa.c
        test_module.c)

# Try to locate GMP via pkg-config first, then fall back to common Homebrew paths
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    pkg_check_modules(GMP REQUIRED IMPORTED_TARGET gmp)
    target_link_libraries(RSA PRIVATE PkgConfig::GMP)
else()
    message(WARNING "pkg-config not found; attempting manual GMP lookup in common locations")
    find_path(GMP_INCLUDE_DIR gmp.h
        HINTS
            /opt/homebrew/include
            /usr/local/include
    )
    find_library(GMP_LIBRARY NAMES gmp
        HINTS
            /opt/homebrew/lib
            /usr/local/lib
    )
    if (GMP_INCLUDE_DIR AND GMP_LIBRARY)
        target_include_directories(RSA PRIVATE ${GMP_INCLUDE_DIR})
        target_link_libraries(RSA PRIVATE ${GMP_LIBRARY})
    else()
        message(FATAL_ERROR "GMP not found. Please install gmp and pkg-config (e.g., via Homebrew), or set GMP_INCLUDE_DIR and GMP_LIBRARY.")
    endif()
endif()
