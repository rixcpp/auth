cmake_minimum_required(VERSION 3.20)

project(rix_auth
  VERSION 0.1.0
  DESCRIPTION "Production-ready authentication package for Vix C++ applications"
  LANGUAGES CXX
)

include(GNUInstallDirs)

option(RIX_AUTH_BUILD_EXAMPLES "Build rix/auth examples" ON)
option(RIX_AUTH_BUILD_TESTS "Build rix/auth tests" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

if(NOT TARGET vix::crypto)
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/crypto/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/crypto" vix_crypto_build)
  elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../crypto/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../crypto" vix_crypto_build)
  else()
    find_package(Vix REQUIRED COMPONENTS crypto)
  endif()
endif()

if(NOT TARGET vix::validation)
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/validation/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/validation" vix_validation_build)
  elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../validation/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../validation" vix_validation_build)
  else()
    find_package(Vix REQUIRED COMPONENTS validation)
  endif()
endif()

if(NOT TARGET vix::time)
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/time/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/time" vix_time_build)
  elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../time/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../time" vix_time_build)
  else()
    find_package(Vix REQUIRED COMPONENTS time)
  endif()
endif()

if(NOT TARGET vix::db)
  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/db/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../vix/modules/db" vix_db_build)
  elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../db/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../db" vix_db_build)
  else()
    find_package(Vix REQUIRED COMPONENTS db)
  endif()
endif()

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
    vix::crypto
    vix::validation
    vix::time
    vix::db
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

install(TARGETS rix_auth
  EXPORT RixAuthTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)
