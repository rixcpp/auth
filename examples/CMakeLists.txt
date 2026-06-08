add_executable(rix_auth_basic
  basic.cpp
)

target_link_libraries(rix_auth_basic
  PRIVATE
    rix::auth
)
