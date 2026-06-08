add_executable(rix_auth_basic
  basic.cpp
)

target_compile_features(rix_auth_basic
  PRIVATE
    cxx_std_20
)

target_link_libraries(rix_auth_basic
  PRIVATE
    rix::auth
)

if(NOT MSVC)
  target_compile_options(rix_auth_basic
    PRIVATE
      -Wall
      -Wextra
      -Wpedantic
  )
endif()
