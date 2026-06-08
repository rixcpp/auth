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
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED

#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthResult.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Production password hashing service.
   *
   * PasswordHasher validates password policy and delegates hashing and
   * verification to vix::crypto.
   *
   * It does not store plain-text passwords and should only return encoded
   * password hashes safe for database storage.
   */
  class PasswordHasher
  {
  public:
    /**
     * @brief Construct a password hasher with development defaults.
     */
    PasswordHasher();

    /**
     * @brief Construct a password hasher from auth configuration.
     *
     * @param config Authentication configuration.
     */
    explicit PasswordHasher(const AuthConfig &config);

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
     * @param password_hash Stored encoded password hash.
     * @return true if the password matches.
     */
    [[nodiscard]] bool verify(
        std::string_view password,
        std::string_view password_hash) const;

    /**
     * @brief Return true when the password satisfies the configured policy.
     *
     * @param password Plain-text password.
     * @return true if the password is accepted.
     */
    [[nodiscard]] bool accepts(std::string_view password) const noexcept;

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
     * @brief Return the maximum accepted password length.
     *
     * @return Maximum password length.
     */
    [[nodiscard]] std::size_t max_password_length() const noexcept;

    /**
     * @brief Set the maximum accepted password length.
     *
     * @param value Maximum password length.
     */
    void set_max_password_length(std::size_t value) noexcept;

    /**
     * @brief Return the password hash iteration count.
     *
     * @return PBKDF2 iteration count.
     */
    [[nodiscard]] std::uint32_t iterations() const noexcept;

    /**
     * @brief Set the password hash iteration count.
     *
     * @param value PBKDF2 iteration count.
     */
    void set_iterations(std::uint32_t value) noexcept;

    /**
     * @brief Return the password salt size in bytes.
     *
     * @return Salt size in bytes.
     */
    [[nodiscard]] std::size_t salt_size() const noexcept;

    /**
     * @brief Set the password salt size in bytes.
     *
     * @param value Salt size in bytes.
     */
    void set_salt_size(std::size_t value) noexcept;

    /**
     * @brief Return the derived password hash size in bytes.
     *
     * @return Hash size in bytes.
     */
    [[nodiscard]] std::size_t hash_size() const noexcept;

    /**
     * @brief Set the derived password hash size in bytes.
     *
     * @param value Hash size in bytes.
     */
    void set_hash_size(std::size_t value) noexcept;

  private:
    std::size_t min_password_length_ = 8;
    std::size_t max_password_length_ = 1024;

    std::uint32_t iterations_ = 310000;
    std::size_t salt_size_ = 16;
    std::size_t hash_size_ = 32;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_PASSWORDHASHER_HPP_INCLUDED
