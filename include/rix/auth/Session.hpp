/**
 *
 *  @file Session.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSION_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSION_HPP_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Authenticated user session.
   *
   * Session represents a server-side authenticated session. It stores the
   * session id, related user id, timestamps, and revocation state.
   *
   * The session id is sensitive and must not be logged in production.
   */
  class Session
  {
  public:
    /**
     * @brief Construct an empty session.
     */
    Session() = default;

    /**
     * @brief Construct a session.
     *
     * @param id Stable session identifier.
     * @param user_id Identifier of the authenticated user.
     * @param created_at Unix timestamp in seconds.
     * @param expires_at Unix timestamp in seconds.
     */
    Session(std::string id,
            std::string user_id,
            std::int64_t created_at,
            std::int64_t expires_at);

    /**
     * @brief Return the stable session identifier.
     *
     * @return Session identifier.
     */
    [[nodiscard]] const std::string &id() const noexcept;

    /**
     * @brief Set the stable session identifier.
     *
     * @param value Session identifier.
     */
    void set_id(std::string value);

    /**
     * @brief Return the user identifier attached to this session.
     *
     * @return User identifier.
     */
    [[nodiscard]] const std::string &user_id() const noexcept;

    /**
     * @brief Set the user identifier attached to this session.
     *
     * @param value User identifier.
     */
    void set_user_id(std::string value);

    /**
     * @brief Return the creation timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t created_at() const noexcept;

    /**
     * @brief Set the creation timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_created_at(std::int64_t value) noexcept;

    /**
     * @brief Return the expiration timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t expires_at() const noexcept;

    /**
     * @brief Set the expiration timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_expires_at(std::int64_t value) noexcept;

    /**
     * @brief Return the last seen timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t last_seen_at() const noexcept;

    /**
     * @brief Set the last seen timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_last_seen_at(std::int64_t value) noexcept;

    /**
     * @brief Return whether this session is revoked.
     *
     * @return true if the session is revoked.
     */
    [[nodiscard]] bool revoked() const noexcept;

    /**
     * @brief Set whether this session is revoked.
     *
     * @param value true when the session is revoked.
     */
    void set_revoked(bool value) noexcept;

    /**
     * @brief Return true when the session has the required identity fields.
     *
     * @return true if id and user id are not empty.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Return true when the session has an id.
     *
     * @return true if the id is not empty.
     */
    [[nodiscard]] bool has_id() const noexcept;

    /**
     * @brief Return true when the session has a user id.
     *
     * @return true if the user id is not empty.
     */
    [[nodiscard]] bool has_user_id() const noexcept;

    /**
     * @brief Return true when the session id matches the given value.
     *
     * @param value Session identifier to compare.
     * @return true if the id matches.
     */
    [[nodiscard]] bool has_id(std::string_view value) const noexcept;

    /**
     * @brief Return true when this session belongs to the given user.
     *
     * @param value User identifier to compare.
     * @return true if the user id matches.
     */
    [[nodiscard]] bool belongs_to(std::string_view value) const noexcept;

    /**
     * @brief Return true when the session is expired at the given time.
     *
     * @param now Unix timestamp in seconds.
     * @return true if now is greater than or equal to expires_at.
     */
    [[nodiscard]] bool expired(std::int64_t now) const noexcept;

    /**
     * @brief Return true when the session can be used at the given time.
     *
     * A usable session must be valid, not revoked, and not expired.
     *
     * @param now Unix timestamp in seconds.
     * @return true if the session is usable.
     */
    [[nodiscard]] bool usable(std::int64_t now) const noexcept;

    /**
     * @brief Return true when the session can be refreshed at the given time.
     *
     * A refreshable session must be valid, not revoked, and not expired.
     *
     * @param now Unix timestamp in seconds.
     * @return true if the session can be refreshed.
     */
    [[nodiscard]] bool refreshable(std::int64_t now) const noexcept;

    /**
     * @brief Refresh the session expiration and last seen timestamps.
     *
     * @param now Current Unix timestamp in seconds.
     * @param ttl_seconds Lifetime to add from now.
     */
    void refresh(std::int64_t now, std::int64_t ttl_seconds) noexcept;

    /**
     * @brief Revoke the session.
     */
    void revoke() noexcept;

  private:
    std::string id_;
    std::string user_id_;

    std::int64_t created_at_ = 0;
    std::int64_t expires_at_ = 0;
    std::int64_t last_seen_at_ = 0;

    bool revoked_ = false;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSION_HPP_INCLUDED
