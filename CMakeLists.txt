cmake_minimum_required(VERSION 3.20)

project(rix_auth
  VERSION 0.1.0
  DESCRIPTION "Ready-to-use authentication package for Vix C++ applications"
  LANGUAGES CXX
)

option(RIX_AUTH_BUILD_EXAMPLES "Build rix/auth examples" ON)
option(RIX_AUTH_BUILD_TESTS "Build rix/auth tests" ON)

add_library(rix_auth
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
)

add_library(rix::auth ALIAS rix_auth)

target_compile_features(rix_auth
  PUBLIC
    cxx_std_20
)

target_include_directories(rix_auth
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  if(RIX_AUTH_BUILD_EXAMPLES)
    add_subdirectory(examples)
  endif()

  if(RIX_AUTH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
  endif()
endif()
