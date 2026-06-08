/**
 *
 *  @file DbSessionStore.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBSESSIONSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBSESSIONSTORE_HPP_INCLUDED

#include <rix/auth/SessionStore.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace vix::db
{
  class Database;
  struct ResultRow;
}

namespace rixlib::auth
{
  /**
   * @brief Database-backed session store.
   *
   * DbSessionStore persists authenticated sessions through vix::db.
   * It is intended for real applications where sessions must survive
   * process restarts.
   *
   * The store expects a table named `rix_auth_sessions`. The constructor can
   * create the table automatically when requested.
   */
  class DbSessionStore final : public SessionStore
  {
  public:
    /**
     * @brief Construct a database-backed session store.
     *
     * @param database Vix database facade.
     * @param create_schema true to create the sessions table automatically.
     */
    explicit DbSessionStore(vix::db::Database &database, bool create_schema = true);

    /**
     * @brief Destroy the database-backed session store.
     */
    ~DbSessionStore() override = default;

    DbSessionStore(const DbSessionStore &) = delete;
    DbSessionStore &operator=(const DbSessionStore &) = delete;

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
     * @brief Create the required sessions table if it does not exist.
     *
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus ensure_schema();

  private:
    [[nodiscard]] static Session row_to_session(const vix::db::ResultRow &row);

    [[nodiscard]] static AuthError store_error(std::string message);
    [[nodiscard]] static AuthError invalid_session_error();
    [[nodiscard]] static AuthError empty_session_id_error();
    [[nodiscard]] static AuthError empty_user_id_error();
    [[nodiscard]] static AuthError session_not_found_error();
    [[nodiscard]] static AuthError session_already_exists_error();

    vix::db::Database *database_ = nullptr;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBSESSIONSTORE_HPP_INCLUDED
