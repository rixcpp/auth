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
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_TOKEN_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_TOKEN_HPP_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Authentication token model.
   *
   * Token represents a short-lived or long-lived authentication token.
   * It stores the raw token value, related user id, issuer, timestamps,
   * and revocation state.
   *
   * The token value is sensitive and must never be logged in production.
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
     * @return Issuer name.
     */
    [[nodiscard]] const std::string &issuer() const noexcept;

    /**
     * @brief Set the token issuer.
     *
     * @param value Issuer name.
     */
    void set_issuer(std::string value);

    /**
     * @brief Return the token issue timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t issued_at() const noexcept;

    /**
     * @brief Set the token issue timestamp.
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
     * @brief Return whether the token is revoked.
     *
     * @return true if the token is revoked.
     */
    [[nodiscard]] bool revoked() const noexcept;

    /**
     * @brief Set whether the token is revoked.
     *
     * @param value true when the token is revoked.
     */
    void set_revoked(bool value) noexcept;

    /**
     * @brief Return true when the token has the required identity fields.
     *
     * @return true if value and user id are not empty.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Return true when the token has a value.
     *
     * @return true if token value is not empty.
     */
    [[nodiscard]] bool has_value() const noexcept;

    /**
     * @brief Return true when the token has a user id.
     *
     * @return true if user id is not empty.
     */
    [[nodiscard]] bool has_user_id() const noexcept;

    /**
     * @brief Return true when this token belongs to the given user.
     *
     * @param value User identifier to compare.
     * @return true if the user id matches.
     */
    [[nodiscard]] bool belongs_to(std::string_view value) const noexcept;

    /**
     * @brief Return true when the raw token value matches the given value.
     *
     * @param value Token value to compare.
     * @return true if token value matches.
     */
    [[nodiscard]] bool matches(std::string_view value) const noexcept;

    /**
     * @brief Return true when the issuer matches the given value.
     *
     * @param value Issuer to compare.
     * @return true if issuer matches.
     */
    [[nodiscard]] bool issued_by(std::string_view value) const noexcept;

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
     * @return true if the token is usable.
     */
    [[nodiscard]] bool usable(std::int64_t now) const noexcept;

    /**
     * @brief Revoke the token.
     */
    void revoke() noexcept;

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
