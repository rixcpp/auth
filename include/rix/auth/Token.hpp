/**
 *
 *  @file Token.hpp
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
 *  Token model for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_TOKEN_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_TOKEN_HPP_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Represents an authentication token.
   *
   * Token is a value object used by rix/auth to represent short-lived or
   * long-lived authentication tokens.
   *
   * It intentionally keeps the token payload simple at this level. Signing,
   * verification, hashing, and transport concerns are handled by higher-level
   * auth services or by Vix modules used internally.
   */
  class Token
  {
  public:
    /**
     * @brief Construct an empty token.
     */
    Token() = default;

    /**
     * @brief Construct a token.
     *
     * @param value Raw token value.
     * @param user_id Identifier of the user who owns the token.
     * @param issued_at Unix timestamp in seconds.
     * @param expires_at Unix timestamp in seconds.
     */
    Token(std::string value,
          std::string user_id,
          std::int64_t issued_at,
          std::int64_t expires_at);

    /**
     * @brief Return the raw token value.
     *
     * The returned value is sensitive and must not be logged in production.
     *
     * @return Raw token value.
     */
    [[nodiscard]] const std::string &value() const noexcept;

    /**
     * @brief Set the raw token value.
     *
     * @param value Raw token value.
     */
    void set_value(std::string value);

    /**
     * @brief Return the user identifier attached to this token.
     *
     * @return User identifier.
     */
    [[nodiscard]] const std::string &user_id() const noexcept;

    /**
     * @brief Set the user identifier attached to this token.
     *
     * @param value User identifier.
     */
    void set_user_id(std::string value);

    /**
     * @brief Return the token issuer.
     *
     * @return Token issuer.
     */
    [[nodiscard]] const std::string &issuer() const noexcept;

    /**
     * @brief Set the token issuer.
     *
     * @param value Token issuer.
     */
    void set_issuer(std::string value);

    /**
     * @brief Return the token creation timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t issued_at() const noexcept;

    /**
     * @brief Set the token creation timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_issued_at(std::int64_t value) noexcept;

    /**
     * @brief Return the token expiration timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t expires_at() const noexcept;

    /**
     * @brief Set the token expiration timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_expires_at(std::int64_t value) noexcept;

    /**
     * @brief Return whether the token has been revoked.
     *
     * @return true if the token has been revoked.
     */
    [[nodiscard]] bool revoked() const noexcept;

    /**
     * @brief Set whether the token has been revoked.
     *
     * @param value true when the token is revoked.
     */
    void set_revoked(bool value) noexcept;

    /**
     * @brief Return true when the token has a non-empty value and user id.
     *
     * @return true if the token has the minimum required fields.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Return true when this token belongs to the given user.
     *
     * @param value User identifier to compare.
     * @return true if the user identifier matches.
     */
    [[nodiscard]] bool belongs_to(std::string_view value) const noexcept;

    /**
     * @brief Return true when the token value matches the given value.
     *
     * @param value Token value to compare.
     * @return true if the token value matches.
     */
    [[nodiscard]] bool matches(std::string_view value) const noexcept;

    /**
     * @brief Return true when the token is expired at the given time.
     *
     * @param now Unix timestamp in seconds.
     * @return true if now is greater than or equal to expires_at.
     */
    [[nodiscard]] bool expired(std::int64_t now) const noexcept;

    /**
     * @brief Return true when the token can be used at the given time.
     *
     * A usable token must be valid, not revoked, and not expired.
     *
     * @param now Unix timestamp in seconds.
     * @return true if the token can be used.
     */
    [[nodiscard]] bool usable(std::int64_t now) const noexcept;

  private:
    std::string value_;
    std::string user_id_;
    std::string issuer_;
    std::int64_t issued_at_ = 0;
    std::int64_t expires_at_ = 0;
    bool revoked_ = false;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_TOKEN_HPP_INCLUDED
