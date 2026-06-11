cmake_minimum_required(VERSION 3.16)
project(AES_DLL VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    AES.cpp
    AES_DLL.cpp
    dllmain.cpp
)

set(HEADERS
    AES.h
    AES_DLL.h
)

# Build as shared library
add_library(AES_DLL SHARED ${SOURCES} ${HEADERS})

target_compile_definitions(AES_DLL PRIVATE AES_DLL_EXPORTS)

# Platform-specific settings
if(WIN32)
    target_link_libraries(AES_DLL PRIVATE iphlpapi advapi32)
    set_target_properties(AES_DLL PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS OFF
    )
elseif(UNIX)
    # Linux / macOS: link OpenSSL for SHA-256 and random
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AES_DLL PRIVATE OpenSSL::Crypto)
    target_compile_definitions(AES_DLL PRIVATE AES_DLL_PLATFORM_UNIX)
    # Note: AES_DLL.cpp uses Windows API; a Unix port needs alternative implementations
endif()

# Install rules
install(TARGETS AES_DLL
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES ${HEADERS} DESTINATION include/AES_DLL)
