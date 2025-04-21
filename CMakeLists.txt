cmake_minimum_required(VERSION 3.12)

project(tiny-aes C)

# --- Build Options ---
option(BUILD_C_DEPLOY_ARTIFACTS "Build C shared/static libraries for deployment/installation" OFF)
option(BUILD_C_TEST_EXECUTABLE "Build the standalone C test executable (requires BUILD_C_DEPLOY_ARTIFACTS=ON)" OFF)

# --- Library Configuration (Always needed) ---
# Define options for different AES modes/features. Default to only GCM-required features.
# Note: These might be overridden by CGO flags if NOT BUILD_C_DEPLOY_ARTIFACTS
option(TINY_AES_C_AES128 "Enable AES128" ON)
option(TINY_AES_C_AES192 "Enable AES192" ON)
option(TINY_AES_C_AES256 "Enable AES256" ON)
option(TINY_AES_C_AES512 "Enable non-standard AES512" ON) # Add option for 512
option(TINY_AES_C_CTR "Enable CTR mode (Required for GCM)" ON)
# option(TINY_AES_C_CBC "Enable CBC mode" OFF) # Commented out - not needed for GCM
# option(TINY_AES_C_ECB "Enable ECB mode" OFF) # Commented out - not needed for GCM

# Library target (initially INTERFACE or STATIC, will add sources later)
add_library(tiny_aes_gcm)

target_sources(tiny_aes_gcm PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/aes.h # Public header
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aes.c # Private source
)

target_include_directories(tiny_aes_gcm PUBLIC
    ${CMAKE_CURRENT_LIST_DIR} # Needed to find aes.h
)

# Add compile definitions based on selected options
if(TINY_AES_C_AES128)
    target_compile_definitions(tiny_aes_gcm PRIVATE AES128=1)
endif()
if(TINY_AES_C_AES192)
    target_compile_definitions(tiny_aes_gcm PRIVATE AES192=1)
endif()
if(TINY_AES_C_AES256)
    target_compile_definitions(tiny_aes_gcm PRIVATE AES256=1)
endif()
if(TINY_AES_C_AES512)
    target_compile_definitions(tiny_aes_gcm PRIVATE AES512=1)
endif()
if(TINY_AES_C_CTR)
    target_compile_definitions(tiny_aes_gcm PRIVATE CTR=1)
endif()
# if(TINY_AES_C_CBC)
#     target_compile_definitions(tiny_aes_gcm PRIVATE CBC=1)
# endif()
# if(TINY_AES_C_ECB)
#     target_compile_definitions(tiny_aes_gcm PRIVATE ECB=1)
# endif()

# Add architecture-specific optimization flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    message(STATUS "Enabling x86_64 AES-NI/PCLMULQDQ flags")
    target_compile_options(tiny_aes_gcm PRIVATE -maes -mpclmul)
elif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    message(STATUS "Enabling aarch64 crypto flags")
    target_compile_options(tiny_aes_gcm PRIVATE -march=armv8-a+crypto)
else()
    message(STATUS "No specific architecture optimizations enabled for ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# --- Build Modes ---
if(BUILD_C_DEPLOY_ARTIFACTS)
    message(STATUS "Configuring for C Library Deployment Build")

    # Build the main library as STATIC
    set_target_properties(tiny_aes_gcm PROPERTIES TYPE STATIC)

    # Optionally add a SHARED library target
    add_library(tiny_aes_gcm_shared SHARED)
    target_link_libraries(tiny_aes_gcm_shared PRIVATE tiny_aes_gcm)
    # Ensure PIC is set for the static lib if we build a shared one from it
    set_target_properties(tiny_aes_gcm PROPERTIES POSITION_INDEPENDENT_CODE ON)

    # --- Installation ---
    include(GNUInstallDirs)
    install(TARGETS tiny_aes_gcm tiny_aes_gcm_shared
        EXPORT tiny_aes_gcm_Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    install(FILES aes.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    # Remove aes.hpp from installation if it exists?
    # install(FILES aes.h aes.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(EXPORT tiny_aes_gcm_Targets
        FILE tiny_aes_gcm_Targets.cmake
        NAMESPACE tiny_aes_gcm::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tiny_aes_gcm
    )

    # --- Optional C Test Executable ---
    if(BUILD_C_TEST_EXECUTABLE)
        message(STATUS "Adding C standalone test executable target")
        add_executable(aes_gcm_test_c test_c_standalone.c)
        # Define the guard macro for the test executable's compilation
        target_compile_definitions(aes_gcm_test_c PRIVATE AES_GCM_STANDALONE_TEST=1)
        # Link the test executable against the static library
        target_link_libraries(aes_gcm_test_c PRIVATE tiny_aes_gcm)
        # Optionally enable testing for it
        enable_testing()
        add_test(NAME c_standalone_test COMMAND aes_gcm_test_c)
    endif()

else()
    message(STATUS "Configuring for Cgo Build (Default)")
    # Assume Cgo handles linking. Provide an INTERFACE library
    # CGO will compile aes.c itself. We just provide header locations.
    set_target_properties(tiny_aes_gcm PROPERTIES TYPE INTERFACE)

    # Any specific Cgo flags or settings could go here
    # Example: target_compile_options(tiny_aes_gcm INTERFACE $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>)

    # Add test_package only if not building deploy artifacts
    # if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_package/CMakeLists.txt")
    #     enable_testing()
    #     add_subdirectory(test_package)
    # endif()

endif()
