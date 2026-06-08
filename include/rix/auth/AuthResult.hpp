/**
 *
 *  @file AuthResult.hpp
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
 *  Result type used by rix/auth operations.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHRESULT_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHRESULT_HPP_INCLUDED

#include <rix/auth/AuthError.hpp>

#include <optional>
#include <utility>

namespace rixlib::auth
{
  /**
   * @brief Result object returned by authentication operations.
   *
   * AuthResult stores either a value of type T or an AuthError.
   * It keeps authentication APIs explicit and avoids throwing exceptions
   * for normal business failures such as invalid credentials or expired tokens.
   *
   * @tparam T Value type returned on success.
   */
  template <typename T>
  class AuthResult
  {
  public:
    /**
     * @brief Create a successful result.
     *
     * @param value Success value.
     * @return AuthResult containing the value.
     */
    [[nodiscard]] static AuthResult success(T value)
    {
      AuthResult result;
      result.value_ = std::move(value);
      return result;
    }

    /**
     * @brief Create a failed result.
     *
     * @param error Authentication error.
     * @return AuthResult containing the error.
     */
    [[nodiscard]] static AuthResult failure(AuthError error)
    {
      AuthResult result;
      result.error_ = std::move(error);
      return result;
    }

    /**
     * @brief Return true when the result contains a value.
     *
     * @return true if the operation succeeded.
     */
    [[nodiscard]] bool ok() const noexcept
    {
      return value_.has_value();
    }

    /**
     * @brief Return true when the result contains an error.
     *
     * @return true if the operation failed.
     */
    [[nodiscard]] bool failed() const noexcept
    {
      return !ok();
    }

    /**
     * @brief Return the success value.
     *
     * The caller must check ok() before calling this function.
     *
     * @return Const reference to the success value.
     */
    [[nodiscard]] const T &value() const
    {
      return *value_;
    }

    /**
     * @brief Return the success value.
     *
     * The caller must check ok() before calling this function.
     *
     * @return Mutable reference to the success value.
     */
    [[nodiscard]] T &value()
    {
      return *value_;
    }

    /**
     * @brief Return the authentication error.
     *
     * When the result is successful, this returns an empty AuthError.
     *
     * @return Const reference to the error.
     */
    [[nodiscard]] const AuthError &error() const noexcept
    {
      return error_;
    }

  private:
    std::optional<T> value_;
    AuthError error_;
  };

  /**
   * @brief Result object for operations that only return success or failure.
   *
   * AuthStatus is used when an operation does not need to return a value,
   * for example logout, session deletion, or password update.
   */
  class AuthStatus
  {
  public:
    /**
     * @brief Create a successful status.
     *
     * @return Successful AuthStatus.
     */
    [[nodiscard]] static AuthStatus success()
    {
      return AuthStatus{};
    }

    /**
     * @brief Create a failed status.
     *
     * @param error Authentication error.
     * @return Failed AuthStatus.
     */
    [[nodiscard]] static AuthStatus failure(AuthError error)
    {
      AuthStatus status;
      status.error_ = std::move(error);
      return status;
    }

    /**
     * @brief Return true when the operation succeeded.
     *
     * @return true if no error is stored.
     */
    [[nodiscard]] bool ok() const noexcept
    {
      return error_.ok();
    }

    /**
     * @brief Return true when the operation failed.
     *
     * @return true if an error is stored.
     */
    [[nodiscard]] bool failed() const noexcept
    {
      return error_.has_error();
    }

    /**
     * @brief Return the authentication error.
     *
     * @return Const reference to the error.
     */
    [[nodiscard]] const AuthError &error() const noexcept
    {
      return error_;
    }

  private:
    AuthError error_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHRESULT_HPP_INCLUDED
