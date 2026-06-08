/**
 *
 *  @file AuthConfig.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHCONFIG_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHCONFIG_HPP_INCLUDED

#include <cstddef>
#include <cstdint>
#include <string>

namespace rixlib::auth
{
  /**
   * @brief Authentication configuration.
   *
   * AuthConfig controls password policy, session lifetime, token lifetime,
   * issuer name, and production security behavior.
   */
  class AuthConfig
  {
  public:
    /**
     * @brief Construct the default authentication configuration.
     */
    AuthConfig();

    /**
     * @brief Return a local development configuration.
     *
     * Development keeps authentication easy to test while still using the same
     * production-grade crypto primitives.
     *
     * @return Development configuration.
     */
    [[nodiscard]] static AuthConfig development();

    /**
     * @brief Return a stricter production configuration.
     *
     * Production enables safer defaults for real applications.
     *
     * @return Production configuration.
     */
    [[nodiscard]] static AuthConfig production();

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
     * @brief Return the session lifetime in seconds.
     *
     * @return Session lifetime in seconds.
     */
    [[nodiscard]] std::int64_t session_ttl_seconds() const noexcept;

    /**
     * @brief Set the session lifetime in seconds.
     *
     * @param value Session lifetime in seconds.
     */
    void set_session_ttl_seconds(std::int64_t value) noexcept;

    /**
     * @brief Return the token lifetime in seconds.
     *
     * @return Token lifetime in seconds.
     */
    [[nodiscard]] std::int64_t token_ttl_seconds() const noexcept;

    /**
     * @brief Set the token lifetime in seconds.
     *
     * @param value Token lifetime in seconds.
     */
    void set_token_ttl_seconds(std::int64_t value) noexcept;

    /**
     * @brief Return the password hashing iteration count.
     *
     * @return PBKDF2 iteration count.
     */
    [[nodiscard]] std::uint32_t password_hash_iterations() const noexcept;

    /**
     * @brief Set the password hashing iteration count.
     *
     * @param value PBKDF2 iteration count.
     */
    void set_password_hash_iterations(std::uint32_t value) noexcept;

    /**
     * @brief Return the password hash salt size in bytes.
     *
     * @return Salt size in bytes.
     */
    [[nodiscard]] std::size_t password_salt_size() const noexcept;

    /**
     * @brief Set the password hash salt size in bytes.
     *
     * @param value Salt size in bytes.
     */
    void set_password_salt_size(std::size_t value) noexcept;

    /**
     * @brief Return the password derived hash size in bytes.
     *
     * @return Derived hash size in bytes.
     */
    [[nodiscard]] std::size_t password_hash_size() const noexcept;

    /**
     * @brief Set the password derived hash size in bytes.
     *
     * @param value Derived hash size in bytes.
     */
    void set_password_hash_size(std::size_t value) noexcept;

    /**
     * @brief Return the issuer used for tokens.
     *
     * @return Issuer name.
     */
    [[nodiscard]] const std::string &issuer() const noexcept;

    /**
     * @brief Set the issuer used for tokens.
     *
     * @param value Issuer name.
     */
    void set_issuer(std::string value);

    /**
     * @brief Return whether email verification is required before login.
     *
     * @return true if email verification is required.
     */
    [[nodiscard]] bool require_email_verification() const noexcept;

    /**
     * @brief Enable or disable email verification before login.
     *
     * @param value true to require email verification.
     */
    void set_require_email_verification(bool value) noexcept;

    /**
     * @brief Return whether session rotation is enabled.
     *
     * @return true if session rotation is enabled.
     */
    [[nodiscard]] bool rotate_sessions() const noexcept;

    /**
     * @brief Enable or disable session rotation.
     *
     * @param value true to enable session rotation.
     */
    void set_rotate_sessions(bool value) noexcept;

    /**
     * @brief Return whether inactive users are blocked from login.
     *
     * @return true if inactive users cannot login.
     */
    [[nodiscard]] bool reject_inactive_users() const noexcept;

    /**
     * @brief Enable or disable inactive user rejection.
     *
     * @param value true to block inactive users from login.
     */
    void set_reject_inactive_users(bool value) noexcept;

  private:
    std::size_t min_password_length_ = 12;
    std::size_t max_password_length_ = 1024;

    std::int64_t session_ttl_seconds_ = 60 * 60 * 24 * 7;
    std::int64_t token_ttl_seconds_ = 60 * 10;

    std::uint32_t password_hash_iterations_ = 310000;
    std::size_t password_salt_size_ = 16;
    std::size_t password_hash_size_ = 32;

    std::string issuer_ = "rix/auth";

    bool require_email_verification_ = false;
    bool rotate_sessions_ = true;
    bool reject_inactive_users_ = true;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHCONFIG_HPP_INCLUDED
