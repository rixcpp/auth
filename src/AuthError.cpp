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
      : code_(code), message_(std::move(message))
  {
  }

  bool AuthError::has_error() const noexcept
  {
    return code_ != AuthErrorCode::None;
  }

  bool AuthError::ok() const noexcept
  {
    return code_ == AuthErrorCode::None;
  }

  AuthErrorCode AuthError::code() const noexcept
  {
    return code_;
  }

  const std::string &AuthError::message() const noexcept
  {
    return message_;
  }

  std::string_view to_string(AuthErrorCode code) noexcept
  {
    switch (code)
    {
    case AuthErrorCode::None:
      return "None";
    case AuthErrorCode::InvalidInput:
      return "InvalidInput";
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
    case AuthErrorCode::InvalidSession:
      return "InvalidSession";
    case AuthErrorCode::SessionExpired:
      return "SessionExpired";
    case AuthErrorCode::InvalidToken:
      return "InvalidToken";
    case AuthErrorCode::TokenExpired:
      return "TokenExpired";
    case AuthErrorCode::InvalidState:
      return "InvalidState";
    case AuthErrorCode::StoreError:
      return "StoreError";
    case AuthErrorCode::Unknown:
      return "Unknown";
    }

    return "Unknown";
  }

  AuthError make_auth_ok()
  {
    return AuthError{};
  }

  AuthError make_auth_error(AuthErrorCode code, std::string message)
  {
    return AuthError{code, std::move(message)};
  }
} // namespace rixlib::auth
