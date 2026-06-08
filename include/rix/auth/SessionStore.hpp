/**
 *
 *  @file SessionStore.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSIONSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSIONSTORE_HPP_INCLUDED

#include <rix/auth/AuthResult.hpp>
#include <rix/auth/Session.hpp>

#include <optional>
#include <string_view>
#include <vector>

namespace rixlib::auth
{
  /**
   * @brief Abstract session storage interface.
   *
   * SessionStore defines the persistence contract used by rix/auth for
   * creating, updating, revoking, deleting, and finding authenticated sessions.
   *
   * Concrete implementations can be backed by memory, database storage,
   * local durable KV storage, or another session backend.
   */
  class SessionStore
  {
  public:
    /**
     * @brief Destroy the session store.
     */
    virtual ~SessionStore();

    /**
     * @brief Create a new session.
     *
     * @param session Session to create.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus create(const Session &session) = 0;

    /**
     * @brief Update an existing session.
     *
     * @param session Session to update.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus update(const Session &session) = 0;

    /**
     * @brief Remove a session by identifier.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus remove_by_id(std::string_view id) = 0;

    /**
     * @brief Revoke a session by identifier.
     *
     * A revoked session remains stored but can no longer be used.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus revoke_by_id(std::string_view id) = 0;

    /**
     * @brief Revoke all sessions belonging to a user.
     *
     * @param user_id User identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus revoke_by_user_id(std::string_view user_id) = 0;

    /**
     * @brief Find a session by identifier.
     *
     * @param id Session identifier.
     * @return Optional session when found, empty optional otherwise.
     */
    [[nodiscard]] virtual AuthResult<std::optional<Session>>
    find_by_id(std::string_view id) const = 0;

    /**
     * @brief Find all sessions belonging to a user.
     *
     * @param user_id User identifier.
     * @return AuthResult containing matching sessions.
     */
    [[nodiscard]] virtual AuthResult<std::vector<Session>>
    find_by_user_id(std::string_view user_id) const = 0;

    /**
     * @brief Return true when a session exists with the given identifier.
     *
     * @param id Session identifier.
     * @return AuthResult containing true when a matching session exists.
     */
    [[nodiscard]] virtual AuthResult<bool>
    exists_by_id(std::string_view id) const = 0;

    /**
     * @brief Return all stored sessions.
     *
     * This is mainly useful for tests, small stores, admin tools, cleanup jobs,
     * and future migration utilities. Large production stores should prefer
     * pagination in a dedicated higher-level API.
     *
     * @return AuthResult containing all sessions.
     */
    [[nodiscard]] virtual AuthResult<std::vector<Session>> all() const = 0;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSIONSTORE_HPP_INCLUDED
