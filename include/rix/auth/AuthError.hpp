/**
 *
 *  @file AuthError.hpp
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
 *  Authentication error model for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED

#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Authentication error category.
   *
   * AuthErrorCode describes the reason why an authentication operation failed.
   * It is intentionally small and stable so applications can safely switch on it.
   */
  enum class AuthErrorCode
  {
    /**
     * @brief No error occurred.
     */
    None,

    /**
     * @brief The input provided by the caller is invalid.
     */
    InvalidInput,

    /**
     * @brief The email address is invalid.
     */
    InvalidEmail,

    /**
     * @brief The password is invalid or too weak.
     */
    InvalidPassword,

    /**
     * @brief The requested user was not found.
     */
    UserNotFound,

    /**
     * @brief A user already exists for the given identity.
     */
    UserAlreadyExists,

    /**
     * @brief The provided credentials are invalid.
     */
    InvalidCredentials,

    /**
     * @brief The session is invalid.
     */
    InvalidSession,

    /**
     * @brief The session has expired.
     */
    SessionExpired,

    /**
     * @brief The provided token is invalid.
     */
    InvalidToken,

    /**
     * @brief The provided token has expired.
     */
    TokenExpired,

    /**
     * @brief The operation cannot be completed in the current state.
     */
    InvalidState,

    /**
     * @brief The storage layer failed.
     */
    StoreError,

    /**
     * @brief An unknown error occurred.
     */
    Unknown
  };

  /**
   * @brief Rich authentication error value.
   *
   * AuthError stores a stable error code and a human-readable message.
   * The code is intended for programmatic decisions, while the message is
   * intended for logs and debugging.
   */
  class AuthError
  {
  public:
    /**
     * @brief Construct an empty error.
     */
    AuthError() = default;

    /**
     * @brief Construct an authentication error.
     *
     * @param code Stable error code.
     * @param message Human-readable error message.
     */
    AuthError(AuthErrorCode code, std::string message);

    /**
     * @brief Return true when this object represents an error.
     *
     * @return true if the error code is not AuthErrorCode::None.
     */
    [[nodiscard]] bool has_error() const noexcept;

    /**
     * @brief Return true when this object does not represent an error.
     *
     * @return true if the error code is AuthErrorCode::None.
     */
    [[nodiscard]] bool ok() const noexcept;

    /**
     * @brief Return the stable error code.
     *
     * @return The error code.
     */
    [[nodiscard]] AuthErrorCode code() const noexcept;

    /**
     * @brief Return the human-readable error message.
     *
     * @return The error message.
     */
    [[nodiscard]] const std::string &message() const noexcept;

  private:
    AuthErrorCode code_ = AuthErrorCode::None;
    std::string message_;
  };

  /**
   * @brief Return a string name for an authentication error code.
   *
   * @param code Error code to convert.
   * @return Stable string representation of the error code.
   */
  [[nodiscard]] std::string_view to_string(AuthErrorCode code) noexcept;

  /**
   * @brief Create an empty authentication error.
   *
   * @return An AuthError with AuthErrorCode::None.
   */
  [[nodiscard]] AuthError make_auth_ok();

  /**
   * @brief Create an authentication error.
   *
   * @param code Stable error code.
   * @param message Human-readable error message.
   * @return AuthError containing the given code and message.
   */
  [[nodiscard]] AuthError make_auth_error(AuthErrorCode code, std::string message);
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED
