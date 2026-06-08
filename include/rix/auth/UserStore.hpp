/**
 *
 *  @file UserStore.hpp
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
 *  User storage interface for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_USERSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_USERSTORE_HPP_INCLUDED

#include <rix/auth/AuthResult.hpp>
#include <rix/auth/User.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rixlib::auth
{
  /**
   * @brief Abstract storage interface for users.
   *
   * UserStore defines the persistence contract used by rix/auth to create,
   * find, update, and delete users.
   *
   * The goal is to keep Auth simple for developers while allowing the storage
   * implementation to evolve independently. Applications can later provide
   * stores backed by memory, files, SQLite, MySQL, PostgreSQL, Redis, or any
   * Vix-based storage module without changing the public Auth API.
   */
  class UserStore
  {
  public:
    /**
     * @brief Destroy the user store.
     */
    virtual ~UserStore();

    /**
     * @brief Save a new user.
     *
     * @param user User to create.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus create(const User &user) = 0;

    /**
     * @brief Update an existing user.
     *
     * @param user User to update.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus update(const User &user) = 0;

    /**
     * @brief Delete a user by identifier.
     *
     * @param id User identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] virtual AuthStatus remove_by_id(std::string_view id) = 0;

    /**
     * @brief Find a user by identifier.
     *
     * @param id User identifier.
     * @return Optional user when found, empty optional otherwise.
     */
    [[nodiscard]] virtual AuthResult<std::optional<User>>
    find_by_id(std::string_view id) const = 0;

    /**
     * @brief Find a user by email address.
     *
     * @param email User email address.
     * @return Optional user when found, empty optional otherwise.
     */
    [[nodiscard]] virtual AuthResult<std::optional<User>>
    find_by_email(std::string_view email) const = 0;

    /**
     * @brief Return true when a user exists for the given identifier.
     *
     * @param id User identifier.
     * @return AuthResult containing true when a matching user exists.
     */
    [[nodiscard]] virtual AuthResult<bool>
    exists_by_id(std::string_view id) const = 0;

    /**
     * @brief Return true when a user exists for the given email address.
     *
     * @param email User email address.
     * @return AuthResult containing true when a matching user exists.
     */
    [[nodiscard]] virtual AuthResult<bool>
    exists_by_email(std::string_view email) const = 0;

    /**
     * @brief Return all stored users.
     *
     * This function is mainly useful for small stores, tests, admin tools,
     * and future migrations. Large production stores may implement pagination
     * later through a dedicated store type.
     *
     * @return AuthResult containing the list of users.
     */
    [[nodiscard]] virtual AuthResult<std::vector<User>> all() const = 0;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_USERSTORE_HPP_INCLUDED
