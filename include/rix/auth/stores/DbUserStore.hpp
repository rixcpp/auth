/**
 *
 *  @file DbUserStore.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBUSERSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBUSERSTORE_HPP_INCLUDED

#include <rix/auth/UserStore.hpp>

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
   * @brief Database-backed user store.
   *
   * DbUserStore persists users through vix::db. It is intended for real
   * applications where users must survive process restarts.
   *
   * The store expects a table named `rix_auth_users`. The constructor can
   * create the table automatically when requested.
   */
  class DbUserStore final : public UserStore
  {
  public:
    /**
     * @brief Construct a database-backed user store.
     *
     * @param database Vix database facade.
     * @param create_schema true to create the users table automatically.
     */
    explicit DbUserStore(vix::db::Database &database, bool create_schema = true);

    /**
     * @brief Destroy the database-backed user store.
     */
    ~DbUserStore() override = default;

    DbUserStore(const DbUserStore &) = delete;
    DbUserStore &operator=(const DbUserStore &) = delete;

    /**
     * @brief Create a new user.
     *
     * @param user User to create.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus create(const User &user) override;

    /**
     * @brief Update an existing user.
     *
     * @param user User to update.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus update(const User &user) override;

    /**
     * @brief Remove a user by identifier.
     *
     * @param id User identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus remove_by_id(std::string_view id) override;

    /**
     * @brief Find a user by identifier.
     *
     * @param id User identifier.
     * @return Optional user when found.
     */
    [[nodiscard]] AuthResult<std::optional<User>>
    find_by_id(std::string_view id) const override;

    /**
     * @brief Find a user by email address.
     *
     * @param email User email address.
     * @return Optional user when found.
     */
    [[nodiscard]] AuthResult<std::optional<User>>
    find_by_email(std::string_view email) const override;

    /**
     * @brief Return true when a user exists by identifier.
     *
     * @param id User identifier.
     * @return AuthResult containing the existence state.
     */
    [[nodiscard]] AuthResult<bool>
    exists_by_id(std::string_view id) const override;

    /**
     * @brief Return true when a user exists by email.
     *
     * @param email User email address.
     * @return AuthResult containing the existence state.
     */
    [[nodiscard]] AuthResult<bool>
    exists_by_email(std::string_view email) const override;

    /**
     * @brief Return all stored users.
     *
     * @return AuthResult containing all users.
     */
    [[nodiscard]] AuthResult<std::vector<User>> all() const override;

    /**
     * @brief Create the required users table if it does not exist.
     *
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus ensure_schema();

  private:
    [[nodiscard]] static User row_to_user(const vix::db::ResultRow &row);

    [[nodiscard]] static AuthError store_error(std::string message);
    [[nodiscard]] static AuthError invalid_user_error();
    [[nodiscard]] static AuthError empty_id_error();
    [[nodiscard]] static AuthError empty_email_error();
    [[nodiscard]] static AuthError user_not_found_error();
    [[nodiscard]] static AuthError user_already_exists_error();

    vix::db::Database *database_ = nullptr;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_DBUSERSTORE_HPP_INCLUDED
