cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(xtt
        VERSION "0.3.1"
        )
set(PROJECT_VERSION_PACKAGE_REVISION 1)

set(XTT_VERSION ${PROJECT_VERSION})
set(XTT_SOVERSION ${PROJECT_VERSION_MAJOR})

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

include(GNUInstallDirs)
include(CTest)

option(USE_LIBSODIUM "use libsodium for aead-related crypto" ON)
option(USE_WOLFCRYPT "use wolfCrypt for aead-related crypto" OFF)
option(USE_ECDAA "use ECDAA for daa-related crypto" ON)
option(USE_TPM "use a TPM" ON)

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

if(USE_LIBSODIUM AND NOT USE_WOLFCRYPT)
        set(CRYPTO_LIB_SRCS libsodium_wrapper.c)
elseif(USE_WOLFCRYPT AND NOT USE_LIBSODIUM)
        # set(CRYPTO_LIB_SRCS wolfcrypt_wrapper.c)
        MESSAGE(FATAL_ERROR "WolfCrypt not currently supported")
else()
        MESSAGE(FATAL_ERROR "Must choose either USE_LIBSODIUM or USE_WOLFCRYPT")
endif()

if(USE_TPM)
        add_definitions(-DUSE_TPM)
        find_package(XaptumTPM REQUIRED QUIET)
        set(ECDAA_ENABLE_TPM ON CACHE BOOL "" FORCE)
else()
        set(ECDAA_ENABLE_TPM OFF CACHE BOOL "" FORCE)
endif()

if(USE_ECDAA)
        set(DAA_LIB_SRCS ecdaa_wrapper.c)
        find_package(AMCL REQUIRED QUIET)
        find_package(ECDAA REQUIRED QUIET)
else()
        MESSAGE(FATAL_ERROR "Only ECDAA is currently supported for DAA signatures")
endif()

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -std=c99 -Wno-missing-field-initializers" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

if(XTT_SESSION_BUFFER_SIZE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSESSION_CONTEXT_BUFFER_SIZE=${XTT_SESSION_BUFFER_SIZE}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSESSION_CONTEXT_BUFFER_SIZE=${XTT_SESSION_BUFFER_SIZE}")
endif()

if(XTT_HANDSHAKE_BUFFER_SIZE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHANDSHAKE_CONTEXT_BUFFER_SIZE=${XTT_HANDSHAKE_BUFFER_SIZE}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHANDSHAKE_CONTEXT_BUFFER_SIZE=${XTT_HANDSHAKE_BUFFER_SIZE}")
endif()

set(XTT_SRCS
        src/${CRYPTO_LIB_SRCS}
        src/${DAA_LIB_SRCS}
        src/certificates.c
        src/context.c
        src/crypto_types.c
        src/messages.c
        src/internal/byte_utils.c
        # src/internal/hashes.c
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
    $<BUILD_INTERFACE:${ECDAA_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${AMCL_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${XAPTUM_TPM_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_link_libraries(xtt
          PRIVATE sodium 
          ${ECDAA_LIBRARIES}
          ${XAPTUM_TPM_LIBRARIES}
  )

  install(TARGETS xtt 
          EXPORT ${CMAKE_PROJECT_NAME}Targets
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
    $<BUILD_INTERFACE:${ECDAA_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${AMCL_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${XAPTUM_TPM_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  target_link_libraries(xtt_static
          PRIVATE sodium 
  )

  install(TARGETS xtt_static
          EXPORT ${CMAKE_PROJECT_NAME}Targets
          RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
          LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
          ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )
endif()

################################################################################
# Examples
################################################################################
if(BUILD_EXAMPLES)
        add_subdirectory(examples)
endif()

# add_subdirectory(test)
