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
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED

#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Stable authentication error codes.
   *
   * These codes are part of the public rix/auth API. They describe
   * authentication-domain failures, not low-level implementation details.
   */
  enum class AuthErrorCode
  {
    None,

    InvalidInput,
    InvalidEmail,
    InvalidPassword,

    UserNotFound,
    UserAlreadyExists,

    InvalidCredentials,
    EmailVerificationRequired,
    UserDisabled,

    InvalidSession,
    SessionExpired,
    SessionRevoked,

    InvalidToken,
    TokenExpired,
    TokenRevoked,

    StoreError,
    CryptoError,
    ValidationError,
    ConfigurationError,

    Unknown
  };

  /**
   * @brief Authentication error value.
   *
   * AuthError stores a stable error code and a human-readable message.
   * The code is intended for programmatic decisions. The message is intended
   * for logs, diagnostics, and developer feedback.
   */
  class AuthError
  {
  public:
    /**
     * @brief Construct a success error value.
     */
    AuthError() = default;

    /**
     * @brief Construct an authentication error.
     *
     * @param code Stable authentication error code.
     * @param message Human-readable error message.
     */
    AuthError(AuthErrorCode code, std::string message);

    /**
     * @brief Return true when this value represents success.
     *
     * @return true if code is AuthErrorCode::None.
     */
    [[nodiscard]] bool ok() const noexcept;

    /**
     * @brief Return true when this value represents failure.
     *
     * @return true if code is not AuthErrorCode::None.
     */
    [[nodiscard]] bool has_error() const noexcept;

    /**
     * @brief Return the stable error code.
     *
     * @return Authentication error code.
     */
    [[nodiscard]] AuthErrorCode code() const noexcept;

    /**
     * @brief Return the human-readable error message.
     *
     * @return Error message.
     */
    [[nodiscard]] const std::string &message() const noexcept;

    /**
     * @brief Return true when the error code equals the given code.
     *
     * @param code Error code to compare.
     * @return true if the stored code matches.
     */
    [[nodiscard]] bool is(AuthErrorCode code) const noexcept;

  private:
    AuthErrorCode code_ = AuthErrorCode::None;
    std::string message_;
  };

  /**
   * @brief Convert an authentication error code to a stable string.
   *
   * @param code Error code.
   * @return Stable string representation.
   */
  [[nodiscard]] std::string_view to_string(AuthErrorCode code) noexcept;

  /**
   * @brief Create a success authentication error value.
   *
   * @return AuthError with AuthErrorCode::None.
   */
  [[nodiscard]] AuthError make_auth_ok();

  /**
   * @brief Create an authentication error.
   *
   * @param code Stable authentication error code.
   * @param message Human-readable error message.
   * @return AuthError value.
   */
  [[nodiscard]] AuthError make_auth_error(
      AuthErrorCode code,
      std::string message);

} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHERROR_HPP_INCLUDED
