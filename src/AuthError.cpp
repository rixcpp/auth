/**
 *
 *  @file AuthError.cpp
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

#include <rix/auth/AuthError.hpp>

#include <utility>

namespace rixlib::auth
{
  AuthError::AuthError(AuthErrorCode code, std::string message)
      : code_(code),
        message_(std::move(message))
  {
  }

  bool AuthError::ok() const noexcept
  {
    return code_ == AuthErrorCode::None;
  }

  bool AuthError::has_error() const noexcept
  {
    return !ok();
  }

  AuthErrorCode AuthError::code() const noexcept
  {
    return code_;
  }

  const std::string &AuthError::message() const noexcept
  {
    return message_;
  }

  bool AuthError::is(AuthErrorCode code) const noexcept
  {
    return code_ == code;
  }

  std::string_view to_string(AuthErrorCode code) noexcept
  {
    switch (code)
    {
    case AuthErrorCode::None:
      return "None";

    case AuthErrorCode::InvalidInput:
      return "InvalidInput";
    case AuthErrorCode::InvalidState:
      return "invalid_state";
    case AuthErrorCode::InvalidEmail:
      return "InvalidEmail";
    case AuthErrorCode::InvalidPassword:
      return "InvalidPassword";

    case AuthErrorCode::UserNotFound:
      return "UserNotFound";
    case AuthErrorCode::UserAlreadyExists:
      return "UserAlreadyExists";

    case AuthErrorCode::InvalidCredentials:
      return "InvalidCredentials";
    case AuthErrorCode::EmailVerificationRequired:
      return "EmailVerificationRequired";
    case AuthErrorCode::UserDisabled:
      return "UserDisabled";

    case AuthErrorCode::InvalidSession:
      return "InvalidSession";
    case AuthErrorCode::SessionExpired:
      return "SessionExpired";
    case AuthErrorCode::SessionRevoked:
      return "SessionRevoked";

    case AuthErrorCode::InvalidToken:
      return "InvalidToken";
    case AuthErrorCode::TokenExpired:
      return "TokenExpired";
    case AuthErrorCode::TokenRevoked:
      return "TokenRevoked";

    case AuthErrorCode::StoreError:
      return "StoreError";
    case AuthErrorCode::CryptoError:
      return "CryptoError";
    case AuthErrorCode::ValidationError:
      return "ValidationError";
    case AuthErrorCode::ConfigurationError:
      return "ConfigurationError";

    case AuthErrorCode::Unknown:
      return "Unknown";
    }

    return "Unknown";
  }

  AuthError make_auth_ok()
  {
    return AuthError{};
  }

  AuthError make_auth_error(
      AuthErrorCode code,
      std::string message)
  {
    return AuthError{code, std::move(message)};
  }
} // namespace rixlib::auth
