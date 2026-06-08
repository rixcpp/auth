/**
 *
 *  @file basic.cpp
 *  @author Gaspard Kirira
 *
 *  Copyright 2026, Gaspard Kirira.
 *  All rights reserved.
 *  https://github.com/rixcpp/auth
 *
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 *
 *  Rix
 *
 */

#include <rix/auth/Auth.hpp>
#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthError.hpp>
#include <rix/auth/stores/MemorySessionStore.hpp>
#include <rix/auth/stores/MemoryUserStore.hpp>

#include <iostream>
#include <string>

namespace
{
  void print_error(const rixlib::auth::AuthError &error)
  {
    std::cerr << "auth error: "
              << rixlib::auth::to_string(error.code())
              << ": "
              << error.message()
              << '\n';
  }

  rixlib::auth::AuthConfig make_auth_config()
  {
    auto config = rixlib::auth::AuthConfig::development();

    config.set_min_password_length(8);
    config.set_session_ttl_seconds(60 * 60 * 24 * 7);
    config.set_token_ttl_seconds(60 * 15);
    config.set_issuer("rix/auth/example");
    config.set_require_email_verification(false);
    config.set_rotate_sessions(true);

    return config;
  }

  bool register_user(rixlib::auth::Auth &auth)
  {
    const auto result = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "correct-password"});

    if (result.failed())
    {
      print_error(result.error());
      return false;
    }

    const auto &user = result.value();

    std::cout << "registered user\n";
    std::cout << "  id: " << user.id() << '\n';
    std::cout << "  email: " << user.email() << '\n';
    std::cout << "  verified: "
              << (user.email_verified() ? "yes" : "no")
              << '\n';

    return true;
  }

  bool login_user(
      rixlib::auth::Auth &auth,
      std::string &session_id)
  {
    const auto result = auth.login(
        rixlib::auth::LoginRequest{
            "ada@example.com",
            "correct-password"});

    if (result.failed())
    {
      print_error(result.error());
      return false;
    }

    const auto &login = result.value();

    session_id = login.session.id();

    std::cout << "login successful\n";
    std::cout << "  user: " << login.user.email() << '\n';
    std::cout << "  session: " << login.session.id() << '\n';
    std::cout << "  token issuer: " << login.token.issuer() << '\n';

    return true;
  }

  bool authenticate_session(
      rixlib::auth::Auth &auth,
      const std::string &session_id)
  {
    const auto result = auth.authenticate_session(session_id);

    if (result.failed())
    {
      print_error(result.error());
      return false;
    }

    const auto &session = result.value();

    std::cout << "session authenticated\n";
    std::cout << "  session: " << session.id() << '\n';
    std::cout << "  user: " << session.user_id() << '\n';

    return true;
  }

  bool logout_user(
      rixlib::auth::Auth &auth,
      const std::string &session_id)
  {
    const auto status = auth.logout(session_id);

    if (status.failed())
    {
      print_error(status.error());
      return false;
    }

    std::cout << "logout successful\n";
    return true;
  }

  int run_basic_example()
  {
    rixlib::auth::MemoryUserStore users;
    rixlib::auth::MemorySessionStore sessions;

    rixlib::auth::Auth auth{
        users,
        sessions,
        make_auth_config()};

    std::string session_id;

    if (!register_user(auth))
    {
      return 1;
    }

    if (!login_user(auth, session_id))
    {
      return 1;
    }

    if (!authenticate_session(auth, session_id))
    {
      return 1;
    }

    if (!logout_user(auth, session_id))
    {
      return 1;
    }

    return 0;
  }
} // namespace

int main()
{
  return run_basic_example();
}
