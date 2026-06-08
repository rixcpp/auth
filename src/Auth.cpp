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

#include <vix/crypto/hex.hpp>
#include <vix/crypto/random.hpp>
#include <vix/time/Clock.hpp>
#include <vix/validation/Validate.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <utility>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] AuthError invalid_email_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidEmail,
          "Email address is invalid.");
    }

    [[nodiscard]] AuthError invalid_password_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::InvalidPassword,
          std::move(message));
    }

    [[nodiscard]] AuthError invalid_credentials_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidCredentials,
          "Invalid email or password.");
    }

    [[nodiscard]] AuthError invalid_session_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::InvalidSession,
          std::move(message));
    }

    [[nodiscard]] AuthError invalid_state_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::InvalidState,
          std::move(message));
    }

    [[nodiscard]] AuthError crypto_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::CryptoError,
          std::move(message));
    }
  } // namespace

  Auth::Auth(UserStore &users, SessionStore &sessions)
      : Auth(users, sessions, AuthConfig::development())
  {
  }

  Auth::Auth(UserStore &users, SessionStore &sessions, AuthConfig config)
      : users_(&users),
        sessions_(&sessions),
        config_(std::move(config)),
        password_hasher_(config_)
  {
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
          make_auth_error(
              AuthErrorCode::UserAlreadyExists,
              "A user already exists with this email address."));
    }

    auto user_id = make_user_id();

    if (user_id.failed())
    {
      return AuthResult<User>::failure(user_id.error());
    }

    auto password_hash = password_hasher_.hash(request.password);

    if (password_hash.failed())
    {
      return AuthResult<User>::failure(password_hash.error());
    }

    const auto now = now_seconds();

    User user{
        user_id.value(),
        request.email,
        password_hash.value(),
        now};

    user.set_updated_at(now);
    user.set_active(true);
    user.set_email_verified(!config_.require_email_verification());

    auto created = users_->create(user);

    if (created.failed())
    {
      return AuthResult<User>::failure(created.error());
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
      return AuthResult<LoginResult>::failure(invalid_credentials_error());
    }

    User user = found.value().value();

    if (!user.active())
    {
      return AuthResult<LoginResult>::failure(invalid_credentials_error());
    }

    if (config_.require_email_verification() && !user.email_verified())
    {
      return AuthResult<LoginResult>::failure(
          invalid_state_error("Email verification is required before login."));
    }

    if (!password_hasher_.verify(request.password, user.password_hash()))
    {
      return AuthResult<LoginResult>::failure(invalid_credentials_error());
    }

    auto session_id = make_session_id();

    if (session_id.failed())
    {
      return AuthResult<LoginResult>::failure(session_id.error());
    }

    const auto now = now_seconds();

    Session session{
        session_id.value(),
        user.id(),
        now,
        now + config_.session_ttl_seconds()};

    auto created = sessions_->create(session);

    if (created.failed())
    {
      return AuthResult<LoginResult>::failure(created.error());
    }

    auto token = issue_token(user.id());

    if (token.failed())
    {
      return AuthResult<LoginResult>::failure(token.error());
    }

    LoginResult result{
        std::move(user),
        std::move(session),
        token.value()};

    return AuthResult<LoginResult>::success(std::move(result));
  }

  AuthStatus Auth::logout(std::string_view session_id)
  {
    if (session_id.empty())
    {
      return AuthStatus::failure(
          invalid_session_error("Session id cannot be empty."));
    }

    return sessions_->revoke_by_id(session_id);
  }

  AuthStatus Auth::logout_user(std::string_view user_id)
  {
    if (user_id.empty())
    {
      return AuthStatus::failure(
          make_auth_error(
              AuthErrorCode::InvalidInput,
              "User id cannot be empty."));
    }

    return sessions_->revoke_by_user_id(user_id);
  }

  AuthResult<Session> Auth::authenticate_session(std::string_view session_id)
  {
    if (session_id.empty())
    {
      return AuthResult<Session>::failure(
          invalid_session_error("Session id cannot be empty."));
    }

    auto found = sessions_->find_by_id(session_id);

    if (found.failed())
    {
      return AuthResult<Session>::failure(found.error());
    }

    if (!found.value().has_value())
    {
      return AuthResult<Session>::failure(
          invalid_session_error("Session not found."));
    }

    Session session = found.value().value();

    const auto now = now_seconds();

    if (session.revoked())
    {
      return AuthResult<Session>::failure(
          invalid_session_error("Session has been revoked."));
    }

    if (session.expired(now))
    {
      return AuthResult<Session>::failure(
          make_auth_error(
              AuthErrorCode::SessionExpired,
              "Session has expired."));
    }

    session.set_last_seen_at(now);

    auto updated = sessions_->update(session);

    if (updated.failed())
    {
      return AuthResult<Session>::failure(updated.error());
    }

    return AuthResult<Session>::success(std::move(session));
  }

  AuthResult<Session> Auth::refresh_session(std::string_view session_id)
  {
    auto authenticated = authenticate_session(session_id);

    if (authenticated.failed())
    {
      return authenticated;
    }

    Session session = authenticated.value();

    const auto now = now_seconds();

    if (!session.refreshable(now))
    {
      return AuthResult<Session>::failure(
          invalid_session_error("Session cannot be refreshed."));
    }

    session.refresh(now, config_.session_ttl_seconds());

    auto updated = sessions_->update(session);

    if (updated.failed())
    {
      return AuthResult<Session>::failure(updated.error());
    }

    return AuthResult<Session>::success(std::move(session));
  }

  AuthResult<Token> Auth::issue_token(std::string_view user_id)
  {
    if (user_id.empty())
    {
      return AuthResult<Token>::failure(
          make_auth_error(
              AuthErrorCode::InvalidInput,
              "User id cannot be empty."));
    }

    auto token_value = make_token_value();

    if (token_value.failed())
    {
      return AuthResult<Token>::failure(token_value.error());
    }

    const auto now = now_seconds();

    return AuthResult<Token>::success(
        make_token_for_user(
            std::string(user_id),
            now,
            token_value.value()));
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
    const auto email = validate_email(request.email);

    if (email.failed())
    {
      return email;
    }

    const auto password = validate_password_for_register(request.password);

    if (password.failed())
    {
      return password;
    }

    return AuthStatus::success();
  }

  AuthStatus Auth::validate_login_request(
      const LoginRequest &request) const
  {
    const auto email = validate_email(request.email);

    if (email.failed())
    {
      return email;
    }

    if (request.password.empty())
    {
      return AuthStatus::failure(
          invalid_password_error("Password cannot be empty."));
    }

    return AuthStatus::success();
  }

  AuthStatus Auth::validate_email(std::string_view email) const
  {
    const std::string value(email);

    const auto result = vix::validation::validate("email", value)
                            .required("Email address is required.")
                            .email("Email address is invalid.")
                            .length_max(320, "Email address is too long.")
                            .result();

    if (!result.ok())
    {
      return AuthStatus::failure(invalid_email_error());
    }

    return AuthStatus::success();
  }

  AuthStatus Auth::validate_password_for_register(
      std::string_view password) const
  {
    if (password.empty())
    {
      return AuthStatus::failure(
          invalid_password_error("Password cannot be empty."));
    }

    if (!password_hasher_.accepts(password))
    {
      return AuthStatus::failure(
          invalid_password_error(
              "Password does not satisfy the configured password policy."));
    }

    return AuthStatus::success();
  }

  std::int64_t Auth::now_seconds() const noexcept
  {
    return vix::time::SystemClock::now().seconds_since_epoch();
  }

  AuthResult<std::string> Auth::make_user_id() const
  {
    return make_secure_id("user");
  }

  AuthResult<std::string> Auth::make_session_id() const
  {
    return make_secure_id("session");
  }

  AuthResult<std::string> Auth::make_token_value() const
  {
    return make_secure_id("token");
  }

  AuthResult<std::string> Auth::make_secure_id(std::string_view prefix) const
  {
    std::array<std::uint8_t, 32> bytes{};

    auto random = vix::crypto::random_bytes(bytes);

    if (!random.ok())
    {
      return AuthResult<std::string>::failure(
          crypto_error(std::string(random.error().message)));
    }

    std::string out(prefix);
    out.push_back('_');
    out += vix::crypto::hex_lower(bytes);

    return AuthResult<std::string>::success(std::move(out));
  }

  Token Auth::make_token_for_user(
      std::string user_id,
      std::int64_t now,
      std::string value) const
  {
    Token token{
        std::move(value),
        std::move(user_id),
        now,
        now + config_.token_ttl_seconds()};

    token.set_issuer(config_.issuer());

    return token;
  }
} // namespace rixlib::auth
