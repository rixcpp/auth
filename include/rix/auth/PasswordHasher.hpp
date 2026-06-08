/**
 *
 *  @file PasswordHasher.hpp
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
 *  Password hashing helper for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED

#include <rix/auth/AuthResult.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Password hashing component used by rix/auth.
   *
   * PasswordHasher hides password hashing details behind a simple API.
   * Application developers should use Auth instead of calling this class
   * directly in most cases.
   *
   * The current implementation is intentionally simple for the first version
   * of rix/auth. The public API is designed so the internal algorithm can be
   * upgraded later without changing the developer-facing Auth API.
   */
  class PasswordHasher
  {
  public:
    /**
     * @brief Construct a password hasher with default settings.
     */
    PasswordHasher();

    /**
     * @brief Hash a plain-text password.
     *
     * @param password Plain-text password.
     * @return AuthResult containing the encoded password hash.
     */
    [[nodiscard]] AuthResult<std::string> hash(std::string_view password) const;

    /**
     * @brief Verify a plain-text password against a stored hash.
     *
     * @param password Plain-text password.
     * @param password_hash Stored password hash.
     * @return true if the password matches the stored hash.
     */
    [[nodiscard]] bool verify(std::string_view password,
                              std::string_view password_hash) const;

    /**
     * @brief Return the minimum accepted password length.
     *
     * @return Minimum password length.
     */
    [[nodiscard]] std::size_t min_password_length() const noexcept;

    /**
     * @brief Set the minimum accepted password length.
     *
     * @param value Minimum password length.
     */
    void set_min_password_length(std::size_t value) noexcept;

    /**
     * @brief Return true when the password satisfies the minimum policy.
     *
     * @param password Plain-text password.
     * @return true if the password is accepted.
     */
    [[nodiscard]] bool accepts(std::string_view password) const noexcept;

  private:
    std::size_t min_password_length_ = 8;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED
