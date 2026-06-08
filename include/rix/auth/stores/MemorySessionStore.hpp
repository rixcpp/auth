/**
 *
 *  @file MemorySessionStore.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYSESSIONSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYSESSIONSTORE_HPP_INCLUDED

#include <rix/auth/SessionStore.hpp>

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace rixlib::auth
{
  /**
   * @brief In-memory session store.
   *
   * MemorySessionStore is useful for tests, examples, local development,
   * and small applications that do not need durable session persistence.
   *
   * It is thread-safe for individual store operations.
   */
  class MemorySessionStore final : public SessionStore
  {
  public:
    /**
     * @brief Construct an empty in-memory session store.
     */
    MemorySessionStore() = default;

    /**
     * @brief Destroy the in-memory session store.
     */
    ~MemorySessionStore() override = default;

    MemorySessionStore(const MemorySessionStore &) = delete;
    MemorySessionStore &operator=(const MemorySessionStore &) = delete;

    /**
     * @brief Create a new session.
     *
     * @param session Session to create.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus create(const Session &session) override;

    /**
     * @brief Update an existing session.
     *
     * @param session Session to update.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus update(const Session &session) override;

    /**
     * @brief Remove a session by identifier.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus remove_by_id(std::string_view id) override;

    /**
     * @brief Revoke a session by identifier.
     *
     * @param id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus revoke_by_id(std::string_view id) override;

    /**
     * @brief Revoke all sessions belonging to a user.
     *
     * @param user_id User identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus revoke_by_user_id(std::string_view user_id) override;

    /**
     * @brief Find a session by identifier.
     *
     * @param id Session identifier.
     * @return Optional session when found.
     */
    [[nodiscard]] AuthResult<std::optional<Session>>
    find_by_id(std::string_view id) const override;

    /**
     * @brief Find all sessions belonging to a user.
     *
     * @param user_id User identifier.
     * @return AuthResult containing matching sessions.
     */
    [[nodiscard]] AuthResult<std::vector<Session>>
    find_by_user_id(std::string_view user_id) const override;

    /**
     * @brief Return true when a session exists by identifier.
     *
     * @param id Session identifier.
     * @return AuthResult containing the existence state.
     */
    [[nodiscard]] AuthResult<bool>
    exists_by_id(std::string_view id) const override;

    /**
     * @brief Return all stored sessions.
     *
     * @return AuthResult containing all sessions.
     */
    [[nodiscard]] AuthResult<std::vector<Session>> all() const override;

    /**
     * @brief Remove all sessions from memory.
     */
    void clear();

    /**
     * @brief Return the number of stored sessions.
     *
     * @return Session count.
     */
    [[nodiscard]] std::size_t size() const;

    /**
     * @brief Return true when the store is empty.
     *
     * @return true if no sessions are stored.
     */
    [[nodiscard]] bool empty() const;

  private:
    [[nodiscard]] static std::string key(std::string_view value);

    void index_session_locked(const Session &session);
    void unindex_session_locked(const Session &session);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_by_id_;
    std::unordered_map<std::string, std::unordered_set<std::string>> ids_by_user_id_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYSESSIONSTORE_HPP_INCLUDED
