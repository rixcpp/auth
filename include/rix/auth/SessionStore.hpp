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
 *  Session storage interface for rix/auth.
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
   * @brief Abstract storage interface for user sessions.
   *
   * SessionStore defines the persistence contract used by rix/auth to create,
   * find, update, revoke, and delete authenticated sessions.
   *
   * This keeps the developer-facing Auth API simple while allowing different
   * storage backends to be implemented later, such as memory, files, SQLite,
   * MySQL, Redis, or Vix-based storage modules.
   */
  class SessionStore
  {
  public:
    /**
     * @brief Destroy the session store.
     */
    virtual ~SessionStore();

    /**
     * @brief Save a new session.
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
     * @brief Delete a session by identifier.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus remove_by_id(std::string_view id) = 0;

    /**
     * @brief Revoke a session by identifier.
     *
     * A revoked session stays stored but can no longer be used.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus revoke_by_id(std::string_view id) = 0;

    /**
     * @brief Revoke all sessions attached to a user.
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
     * @brief Find all sessions attached to a user.
     *
     * @param user_id User identifier.
     * @return AuthResult containing matching sessions.
     */
    [[nodiscard]] virtual AuthResult<std::vector<Session>>
    find_by_user_id(std::string_view user_id) const = 0;

    /**
     * @brief Return true when a session exists for the given identifier.
     *
     * @param id Session identifier.
     * @return AuthResult containing true when a matching session exists.
     */
    [[nodiscard]] virtual AuthResult<bool>
    exists_by_id(std::string_view id) const = 0;

    /**
     * @brief Return all stored sessions.
     *
     * This function is mainly useful for tests, small stores, admin tools,
     * and future cleanup or migration utilities.
     *
     * @return AuthResult containing the list of sessions.
     */
    [[nodiscard]] virtual AuthResult<std::vector<Session>> all() const = 0;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_SESSIONSTORE_HPP_INCLUDED
