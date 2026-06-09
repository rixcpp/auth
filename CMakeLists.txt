cmake_minimum_required(VERSION 3.20)

project(rix_auth
  VERSION 0.1.0
  DESCRIPTION "Production-ready authentication package for Vix C++ applications"
  LANGUAGES CXX
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

option(RIX_AUTH_BUILD_EXAMPLES "Build rix/auth examples" ON)
option(RIX_AUTH_BUILD_TESTS "Build rix/auth tests" ON)
option(RIX_AUTH_INSTALL "Install rix/auth package" ON)

option(RIX_AUTH_ENABLE_LOCAL_DEPS
  "Allow rix/auth to use explicitly provided local dependency source trees"
  ON
)

set(RIX_AUTH_VIX_SOURCE_DIR
  ""
  CACHE PATH "Optional path to a local Vix source tree"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

function(rix_auth_find_target output_var)
  foreach(candidate IN LISTS ARGN)
    if(TARGET "${candidate}")
      set(${output_var} "${candidate}" PARENT_SCOPE)
      return()
    endif()
  endforeach()

  set(${output_var} "" PARENT_SCOPE)
endfunction()

# ------------------------------------------------------------------------------
# Default dependency prefixes
# ------------------------------------------------------------------------------

set(RIX_AUTH_DEFAULT_PREFIXES)

if(DEFINED ENV{HOME})
  list(APPEND RIX_AUTH_DEFAULT_PREFIXES
    "$ENV{HOME}/.local"
    "$ENV{HOME}/.vix"
  )
endif()

if(DEFINED ENV{LOCALAPPDATA})
  list(APPEND RIX_AUTH_DEFAULT_PREFIXES
    "$ENV{LOCALAPPDATA}/Vix"
  )
endif()

foreach(prefix IN LISTS RIX_AUTH_DEFAULT_PREFIXES)
  if(EXISTS "${prefix}")
    list(PREPEND CMAKE_PREFIX_PATH "${prefix}")
  endif()
endforeach()

list(REMOVE_DUPLICATES CMAKE_PREFIX_PATH)

# ------------------------------------------------------------------------------
# Optional local source tree
# ------------------------------------------------------------------------------

if(RIX_AUTH_ENABLE_LOCAL_DEPS)
  if(NOT "${RIX_AUTH_VIX_SOURCE_DIR}" STREQUAL "")
    if(EXISTS "${RIX_AUTH_VIX_SOURCE_DIR}/CMakeLists.txt")
      add_subdirectory(
        "${RIX_AUTH_VIX_SOURCE_DIR}"
        "${CMAKE_BINARY_DIR}/_deps/vix"
      )
    else()
      message(FATAL_ERROR
        "RIX_AUTH_VIX_SOURCE_DIR is set, but no CMakeLists.txt was found.\n"
        "Path: ${RIX_AUTH_VIX_SOURCE_DIR}"
      )
    endif()
  endif()
endif()

# ------------------------------------------------------------------------------
# Installed packages
# ------------------------------------------------------------------------------

find_package(Vix CONFIG QUIET)

# ------------------------------------------------------------------------------
# Vix dependency targets
# ------------------------------------------------------------------------------

rix_auth_find_target(RIX_AUTH_VIX_TARGET
  vix::vix
  Vix::Vix
  vix
)

rix_auth_find_target(RIX_AUTH_VIX_CRYPTO_TARGET
  vix::crypto
  vix_crypto
)

rix_auth_find_target(RIX_AUTH_VIX_VALIDATION_TARGET
  vix::validation
  vix_validation
)

rix_auth_find_target(RIX_AUTH_VIX_TIME_TARGET
  vix::time
  vix_time
)

rix_auth_find_target(RIX_AUTH_VIX_DB_TARGET
  vix::db
  vix_db
)

if("${RIX_AUTH_VIX_TARGET}" STREQUAL ""
   AND "${RIX_AUTH_VIX_CRYPTO_TARGET}" STREQUAL ""
   AND "${RIX_AUTH_VIX_VALIDATION_TARGET}" STREQUAL ""
   AND "${RIX_AUTH_VIX_TIME_TARGET}" STREQUAL ""
   AND "${RIX_AUTH_VIX_DB_TARGET}" STREQUAL "")
  message(FATAL_ERROR
    "Vix development package was not found.\n"
    "Install Vix first or pass -DRIX_AUTH_VIX_SOURCE_DIR=/path/to/vix.\n"
    "Expected CMake package: VixConfig.cmake\n"
    "Expected target: vix::vix, Vix::Vix, vix, or individual vix::* module targets."
  )
endif()

set(RIX_AUTH_PUBLIC_DEPENDENCIES)

if(NOT "${RIX_AUTH_VIX_TARGET}" STREQUAL "")
  list(APPEND RIX_AUTH_PUBLIC_DEPENDENCIES
    ${RIX_AUTH_VIX_TARGET}
  )
endif()

foreach(candidate
  ${RIX_AUTH_VIX_CRYPTO_TARGET}
  ${RIX_AUTH_VIX_VALIDATION_TARGET}
  ${RIX_AUTH_VIX_TIME_TARGET}
  ${RIX_AUTH_VIX_DB_TARGET}
)
  if(NOT "${candidate}" STREQUAL "")
    list(APPEND RIX_AUTH_PUBLIC_DEPENDENCIES "${candidate}")
  endif()
endforeach()

list(REMOVE_DUPLICATES RIX_AUTH_PUBLIC_DEPENDENCIES)

message(STATUS "[rix/auth] Vix target:     ${RIX_AUTH_VIX_TARGET}")
message(STATUS "[rix/auth] Vix crypto:     ${RIX_AUTH_VIX_CRYPTO_TARGET}")
message(STATUS "[rix/auth] Vix validation: ${RIX_AUTH_VIX_VALIDATION_TARGET}")
message(STATUS "[rix/auth] Vix time:       ${RIX_AUTH_VIX_TIME_TARGET}")
message(STATUS "[rix/auth] Vix db:         ${RIX_AUTH_VIX_DB_TARGET}")
message(STATUS "[rix/auth] Vix deps:       ${RIX_AUTH_PUBLIC_DEPENDENCIES}")

# ------------------------------------------------------------------------------
# Library
# ------------------------------------------------------------------------------

add_library(rix_auth STATIC
  src/Auth.cpp
  src/AuthConfig.cpp
  src/AuthError.cpp
  src/PasswordHasher.cpp
  src/User.cpp
  src/Session.cpp
  src/Token.cpp
  src/UserStore.cpp
  src/SessionStore.cpp
  src/Version.cpp

  src/stores/MemoryUserStore.cpp
  src/stores/MemorySessionStore.cpp
  src/stores/DbUserStore.cpp
  src/stores/DbSessionStore.cpp
)

add_library(rix::auth ALIAS rix_auth)

target_compile_features(rix_auth
  PUBLIC
    cxx_std_20
)

target_include_directories(rix_auth
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(rix_auth
  PUBLIC
    ${RIX_AUTH_PUBLIC_DEPENDENCIES}
)

set_target_properties(rix_auth PROPERTIES
  OUTPUT_NAME rix_auth
  VERSION ${PROJECT_VERSION}
  SOVERSION 0
  EXPORT_NAME auth
)

if(NOT MSVC)
  target_compile_options(rix_auth
    PRIVATE
      -Wall
      -Wextra
      -Wpedantic
  )
endif()

# ------------------------------------------------------------------------------
# Examples and tests
# ------------------------------------------------------------------------------

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  if(RIX_AUTH_BUILD_EXAMPLES)
    add_subdirectory(examples)
  endif()

  if(RIX_AUTH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
  endif()
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(RIX_AUTH_INSTALL)
  install(TARGETS rix_auth
    EXPORT RixAuthTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING
      PATTERN "*.hpp"
      PATTERN "*.h"
  )

  install(EXPORT RixAuthTargets
    FILE RixAuthTargets.cmake
    NAMESPACE rix::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/rix_auth"
  )

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/RixAuthConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RixAuthConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/RixAuthConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/rix_auth"
  )

  install(
    FILES
      "${CMAKE_CURRENT_BINARY_DIR}/RixAuthConfig.cmake"
      "${CMAKE_CURRENT_BINARY_DIR}/RixAuthConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/rix_auth"
  )

  install(
    FILES
      "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
      "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/rix_auth"
    OPTIONAL
  )
endif()
