find_package(GTest QUIET)

if(NOT GTest_FOUND)
  include(FetchContent)

  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  )

  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

  FetchContent_MakeAvailable(googletest)
endif()

add_executable(rix_auth_tests
  UserTests.cpp
  SessionTests.cpp
  TokenTests.cpp
  PasswordHasherTests.cpp
  MemoryUserStoreTests.cpp
  MemorySessionStoreTests.cpp
  AuthTests.cpp
)

target_compile_features(rix_auth_tests
  PRIVATE
    cxx_std_20
)

target_link_libraries(rix_auth_tests
  PRIVATE
    rix::auth
    GTest::gtest_main
)

if(NOT MSVC)
  target_compile_options(rix_auth_tests
    PRIVATE
      -Wall
      -Wextra
      -Wpedantic
  )
endif()

include(GoogleTest)

gtest_discover_tests(rix_auth_tests)
