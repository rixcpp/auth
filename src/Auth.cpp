/**
 *
 *  @file Auth.cpp
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

#include <chrono>
#include <cstddef>
#include <random>
#include <sstream>
#include <utility>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] std::string make_random_id(std::string_view prefix)
    {
      static thread_local std::mt19937_64 engine{
          std::random_device{}()};

      const auto now = std::chrono::system_clock::now()
                           .time_since_epoch()
                           .count();

      const auto value = engine();

      std::ostringstream stream;
      stream << prefix << "_" << now << "_" << value;

      return stream.str();
    }
  } // namespace

  Auth::Auth(UserStore &users, SessionStore &sessions)
      : Auth(users, sessions, AuthConfig::development())
  {
  }

  Auth::Auth(UserStore &users, SessionStore &sessions, AuthConfig config)
      : users_(&users),
        sessions_(&sessions),
        config_(std::move(config))
  {
    password_hasher_.set_min_password_length(config_.min_password_length());
  }

  AuthResult<User> Auth::register_user(const RegisterRequest &request)
  {
    const auto validation = validate_register_request(request);
    if (validation.failed())
    {
      return AuthResult<User>::failure(validation.error());
    }

    auto exists = users_->exists_by_email(request.email);
    if (exists.failed())
    {
      return AuthResult<User>::failure(exists.error());
    }

    if (exists.value())
    {
      return AuthResult<User>::failure(
          make_auth_error(AuthErrorCode::UserAlreadyExists,
                          "A user already exists with this email address."));
    }

    auto password_hash = password_hasher_.hash(request.password);
    if (password_hash.failed())
    {
      return AuthResult<User>::failure(password_hash.error());
    }

    const auto created_at = now_seconds();

    User user{
        make_user_id(),
        request.email,
        password_hash.value(),
        created_at};

    user.set_email_verified(!config_.require_email_verification());
    user.set_active(true);

    auto status = users_->create(user);
    if (status.failed())
    {
      return AuthResult<User>::failure(status.error());
    }

    return AuthResult<User>::success(std::move(user));
  }

  AuthResult<LoginResult> Auth::login(const LoginRequest &request)
  {
    const auto validation = validate_login_request(request);
    if (validation.failed())
    {
      return AuthResult<LoginResult>::failure(validation.error());
    }

    auto found = users_->find_by_email(request.email);
    if (found.failed())
    {
      return AuthResult<LoginResult>::failure(found.error());
    }

    if (!found.value().has_value())
    {
      return AuthResult<LoginResult>::failure(
          make_auth_error(AuthErrorCode::InvalidCredentials,
                          "Invalid email or password."));
    }

    User user = found.value().value();

    if (!user.active())
    {
      return AuthResult<LoginResult>::failure(
          make_auth_error(AuthErrorCode::InvalidCredentials,
                          "Invalid email or password."));
    }

    if (config_.require_email_verification() && !user.email_verified())
    {
      return AuthResult<LoginResult>::failure(
          make_auth_error(AuthErrorCode::InvalidState,
                          "Email verification is required before login."));
    }

    if (!password_hasher_.verify(request.password, user.password_hash()))
    {
      return AuthResult<LoginResult>::failure(
          make_auth_error(AuthErrorCode::InvalidCredentials,
                          "Invalid email or password."));
    }

    const auto now = now_seconds();

    Session session{
        make_session_id(),
        user.id(),
        now,
        now + config_.session_ttl_seconds()};

    auto status = sessions_->create(session);
    if (status.failed())
    {
      return AuthResult<LoginResult>::failure(status.error());
    }

    LoginResult result{
        std::move(user),
        std::move(session)};

    return AuthResult<LoginResult>::success(std::move(result));
  }

  AuthStatus Auth::logout(std::string_view session_id)
  {
    if (session_id.empty())
    {
      return AuthStatus::failure(
          make_auth_error(AuthErrorCode::InvalidSession,
                          "Session id cannot be empty."));
    }

    return sessions_->revoke_by_id(session_id);
  }

  AuthResult<Session> Auth::authenticate_session(std::string_view session_id)
  {
    if (session_id.empty())
    {
      return AuthResult<Session>::failure(
          make_auth_error(AuthErrorCode::InvalidSession,
                          "Session id cannot be empty."));
    }

    auto found = sessions_->find_by_id(session_id);
    if (found.failed())
    {
      return AuthResult<Session>::failure(found.error());
    }

    if (!found.value().has_value())
    {
      return AuthResult<Session>::failure(
          make_auth_error(AuthErrorCode::InvalidSession,
                          "Session not found."));
    }

    Session session = found.value().value();

    if (session.revoked())
    {
      return AuthResult<Session>::failure(
          make_auth_error(AuthErrorCode::InvalidSession,
                          "Session has been revoked."));
    }

    if (session.expired(now_seconds()))
    {
      return AuthResult<Session>::failure(
          make_auth_error(AuthErrorCode::SessionExpired,
                          "Session has expired."));
    }

    session.set_last_seen_at(now_seconds());

    auto status = sessions_->update(session);
    if (status.failed())
    {
      return AuthResult<Session>::failure(status.error());
    }

    return AuthResult<Session>::success(std::move(session));
  }

  const AuthConfig &Auth::config() const noexcept
  {
    return config_;
  }

  const PasswordHasher &Auth::password_hasher() const noexcept
  {
    return password_hasher_;
  }

  AuthStatus Auth::validate_register_request(
      const RegisterRequest &request) const
  {
    if (!is_valid_email(request.email))
    {
      return AuthStatus::failure(
          make_auth_error(AuthErrorCode::InvalidEmail,
                          "Email address is invalid."));
    }

    if (!password_hasher_.accepts(request.password))
    {
      return AuthStatus::failure(
          make_auth_error(AuthErrorCode::InvalidPassword,
                          "Password does not satisfy the minimum length policy."));
    }

    return AuthStatus::success();
  }

  AuthStatus Auth::validate_login_request(
      const LoginRequest &request) const
  {
    if (!is_valid_email(request.email))
    {
      return AuthStatus::failure(
          make_auth_error(AuthErrorCode::InvalidEmail,
                          "Email address is invalid."));
    }

    if (request.password.empty())
    {
      return AuthStatus::failure(
          make_auth_error(AuthErrorCode::InvalidPassword,
                          "Password cannot be empty."));
    }

    return AuthStatus::success();
  }

  bool Auth::is_valid_email(std::string_view email) const noexcept
  {
    const auto at = email.find('@');
    if (at == std::string_view::npos || at == 0 || at + 1 >= email.size())
    {
      return false;
    }

    const auto dot = email.find('.', at + 1);
    return dot != std::string_view::npos && dot + 1 < email.size();
  }

  std::string Auth::make_user_id() const
  {
    return make_random_id("user");
  }

  std::string Auth::make_session_id() const
  {
    return make_random_id("session");
  }

  std::int64_t Auth::now_seconds() const noexcept
  {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch());

    return seconds.count();
  }
} // namespace rixlib::auth
