cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(xtt
        VERSION "0.5.0"
        )
set(PROJECT_VERSION_PACKAGE_REVISION 1)

set(XTT_VERSION ${PROJECT_VERSION})
set(XTT_SOVERSION ${PROJECT_VERSION_MAJOR})


include(GNUInstallDirs)
include(CTest)

option(USE_TPM "use a TPM" ON)

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

find_package(ecdaa 0.8.4 REQUIRED QUIET)
# TODO: Currently, the ecdaa package will find sodium for us
# find_package(sodium 1.0.11 REQUIRED QUIET)

if(USE_TPM)
        add_definitions(-DUSE_TPM)
        set(USE_TPM_DEFINE "#define USE_TPM")
        find_package(xaptum-tpm 0.5.0 REQUIRED QUIET)
endif()

configure_file(${PROJECT_SOURCE_DIR}/include/xtt/context.h.in ${CMAKE_BINARY_DIR}/include/xtt/context.h)
configure_file(${PROJECT_SOURCE_DIR}/include/xtt/daa_wrapper.h.in ${CMAKE_BINARY_DIR}/include/xtt/daa_wrapper.h)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -std=c99 -Wno-missing-field-initializers" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

set(XTT_SRCS
        src/libsodium_wrapper.c
        src/ecdaa_wrapper.c
        src/certificates.c
        src/context.c
        src/crypto_types.c
        src/messages.c
        src/internal/byte_utils.c
        src/internal/key_derivation.c
        src/internal/crypto_utils.c
        src/internal/message_utils.c
        src/internal/server_cookie.c
        src/internal/signatures.c
        )

################################################################################
# Shared Libary
################################################################################
if(BUILD_SHARED_LIBS)
  add_library(xtt SHARED ${XTT_SRCS})

  set_target_properties(xtt PROPERTIES
    VERSION "${XTT_VERSION}"
    SOVERSION "${XTT_SOVERSION}"
  )
  
  target_include_directories(xtt PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_link_libraries(xtt
          PRIVATE sodium 
          PRIVATE ecdaa::ecdaa
          PRIVATE AMCL::AMCL
  )

  if(USE_TPM)
    target_link_libraries(xtt PUBLIC xaptum-tpm::xaptum-tpm)
  endif()

  install(TARGETS xtt 
          EXPORT xtt-targets
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )
endif()

################################################################################
# Static Libary
################################################################################
if(BUILD_STATIC_LIBS)
  add_library(xtt_static STATIC ${XTT_SRCS})

  set_target_properties(xtt_static PROPERTIES
    OUTPUT_NAME "xtt${STATIC_SUFFIX}"
    VERSION "${XTT_VERSION}"
    SOVERSION "${XTT_SOVERSION}"
  )

  target_include_directories(xtt_static PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_link_libraries(xtt_static
          PRIVATE sodium 
          PRIVATE ecdaa::ecdaa
          PRIVATE AMCL::AMCL
  )
  if(USE_TPM)
    target_link_libraries(xtt_static PUBLIC xaptum-tpm::xaptum-tpm)
  endif()

  install(TARGETS xtt_static
          EXPORT xtt-targets
          RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
          LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
          ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )
endif()

################################################################################
# Headers
################################################################################
install(FILES include/xtt.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY include/xtt DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.h")
install(DIRECTORY ${CMAKE_BINARY_DIR}/include/xtt DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

################################################################################
# pkgconfig
################################################################################
configure_file(xtt.pc.in xtt.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xtt.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

################################################################################
# CMake export
################################################################################
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/xtt)

install(EXPORT xtt-targets
        FILE xtt-targets.cmake
        NAMESPACE xtt::
        DESTINATION ${INSTALL_CONFIGDIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-config-version.cmake
  VERSION ${XTT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/xtt-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/xtt-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

################################################################################
# Examples
################################################################################
if(BUILD_EXAMPLES)
        add_subdirectory(examples)
endif()

################################################################################
# Tests
################################################################################
# Current disabled, while moving rapidly. TODO!!!
# add_subdirectory(test)
