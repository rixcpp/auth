/**
 *
 *  @file ManagedAuth.cpp
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

#include <rix/auth/ManagedAuth.hpp>

#include <cassert>
#include <memory>
#include <utility>

namespace rixlib::auth
{
  ManagedAuth::ManagedAuth(
      std::unique_ptr<UserStore> users,
      std::unique_ptr<SessionStore> sessions,
      AuthConfig config)
      : users_(std::move(users)),
        sessions_(std::move(sessions)),
        config_(std::move(config))
  {
    rebuild_service();
  }

  ManagedAuth::ManagedAuth(ManagedAuth &&other) noexcept
      : users_(std::move(other.users_)),
        sessions_(std::move(other.sessions_)),
        config_(std::move(other.config_))
  {
    rebuild_service();
  }

  ManagedAuth &ManagedAuth::operator=(ManagedAuth &&other) noexcept
  {
    if (this == &other)
    {
      return *this;
    }

    users_ = std::move(other.users_);
    sessions_ = std::move(other.sessions_);
    config_ = std::move(other.config_);

    rebuild_service();

    return *this;
  }

  AuthResult<User> ManagedAuth::register_user(
      const RegisterRequest &request)
  {
    return auth_->register_user(request);
  }

  AuthResult<LoginResult> ManagedAuth::login(
      const LoginRequest &request)
  {
    return auth_->login(request);
  }

  AuthStatus ManagedAuth::logout(std::string_view session_id)
  {
    return auth_->logout(session_id);
  }

  AuthStatus ManagedAuth::logout_user(std::string_view user_id)
  {
    return auth_->logout_user(user_id);
  }

  AuthResult<Session> ManagedAuth::authenticate_session(
      std::string_view session_id)
  {
    return auth_->authenticate_session(session_id);
  }

  AuthResult<Session> ManagedAuth::refresh_session(
      std::string_view session_id)
  {
    return auth_->refresh_session(session_id);
  }

  AuthResult<Token> ManagedAuth::issue_token(std::string_view user_id)
  {
    return auth_->issue_token(user_id);
  }

  const AuthConfig &ManagedAuth::config() const noexcept
  {
    return auth_->config();
  }

  const PasswordHasher &ManagedAuth::password_hasher() const noexcept
  {
    return auth_->password_hasher();
  }

  Auth &ManagedAuth::service() noexcept
  {
    return *auth_;
  }

  const Auth &ManagedAuth::service() const noexcept
  {
    return *auth_;
  }

  UserStore &ManagedAuth::users() noexcept
  {
    return *users_;
  }

  const UserStore &ManagedAuth::users() const noexcept
  {
    return *users_;
  }

  SessionStore &ManagedAuth::sessions() noexcept
  {
    return *sessions_;
  }

  const SessionStore &ManagedAuth::sessions() const noexcept
  {
    return *sessions_;
  }

  void ManagedAuth::rebuild_service()
  {
    assert(users_ != nullptr);
    assert(sessions_ != nullptr);

    auth_ = std::make_unique<Auth>(
        *users_,
        *sessions_,
        config_);
  }
} // namespace rixlib::auth
