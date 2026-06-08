add_executable(rix_auth_user_tests
  UserTests.cpp
)

target_link_libraries(rix_auth_user_tests
  PRIVATE
    rix::auth
)

add_test(
  NAME rix_auth_user_tests
  COMMAND rix_auth_user_tests
)

add_executable(rix_auth_session_tests
  SessionTests.cpp
)

target_link_libraries(rix_auth_session_tests
  PRIVATE
    rix::auth
)

add_test(
  NAME rix_auth_session_tests
  COMMAND rix_auth_session_tests
)

add_executable(rix_auth_token_tests
  TokenTests.cpp
)

target_link_libraries(rix_auth_token_tests
  PRIVATE
    rix::auth
)

add_test(
  NAME rix_auth_token_tests
  COMMAND rix_auth_token_tests
)

add_executable(rix_auth_password_hasher_tests
  PasswordHasherTests.cpp
)

target_link_libraries(rix_auth_password_hasher_tests
  PRIVATE
    rix::auth
)

add_test(
  NAME rix_auth_password_hasher_tests
  COMMAND rix_auth_password_hasher_tests
)

add_executable(rix_auth_auth_tests
  AuthTests.cpp
)

target_link_libraries(rix_auth_auth_tests
  PRIVATE
    rix::auth
)

add_test(
  NAME rix_auth_auth_tests
  COMMAND rix_auth_auth_tests
)
