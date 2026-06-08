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
 *  Configuration for rix/auth.
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
   * @brief Configuration used by the authentication service.
   *
   * AuthConfig keeps the package configurable while preserving a simple default
   * experience for application developers.
   */
  class AuthConfig
  {
  public:
    /**
     * @brief Create a configuration with secure default values.
     */
    AuthConfig();

    /**
     * @brief Create the default development configuration.
     *
     * @return AuthConfig with sensible defaults for local development.
     */
    [[nodiscard]] static AuthConfig development();

    /**
     * @brief Create the default production configuration.
     *
     * @return AuthConfig with stricter defaults for production applications.
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
     * @brief Return the issuer name used for generated tokens.
     *
     * @return Token issuer.
     */
    [[nodiscard]] const std::string &issuer() const noexcept;

    /**
     * @brief Set the issuer name used for generated tokens.
     *
     * @param value Token issuer.
     */
    void set_issuer(std::string value);

    /**
     * @brief Return whether email verification is required.
     *
     * @return true if users must verify their email.
     */
    [[nodiscard]] bool require_email_verification() const noexcept;

    /**
     * @brief Enable or disable email verification.
     *
     * @param value true to require email verification.
     */
    void set_require_email_verification(bool value) noexcept;

    /**
     * @brief Return whether session rotation is enabled.
     *
     * @return true if session identifiers may be rotated after sensitive actions.
     */
    [[nodiscard]] bool rotate_sessions() const noexcept;

    /**
     * @brief Enable or disable session rotation.
     *
     * @param value true to enable session rotation.
     */
    void set_rotate_sessions(bool value) noexcept;

  private:
    std::size_t min_password_length_ = 8;
    std::int64_t session_ttl_seconds_ = 60 * 60 * 24 * 7;
    std::int64_t token_ttl_seconds_ = 60 * 15;
    std::string issuer_ = "rix/auth";
    bool require_email_verification_ = false;
    bool rotate_sessions_ = true;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHCONFIG_HPP_INCLUDED
