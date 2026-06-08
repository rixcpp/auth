/**
 *
 *  @file MemoryUserStore.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYUSERSTORE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYUSERSTORE_HPP_INCLUDED

#include <rix/auth/UserStore.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace rixlib::auth
{
  /**
   * @brief In-memory user store.
   *
   * MemoryUserStore is useful for tests, examples, local development,
   * and small applications that do not need durable user persistence.
   *
   * It is thread-safe for individual store operations.
   */
  class MemoryUserStore final : public UserStore
  {
  public:
    /**
     * @brief Construct an empty in-memory user store.
     */
    MemoryUserStore() = default;

    /**
     * @brief Destroy the in-memory user store.
     */
    ~MemoryUserStore() override = default;

    MemoryUserStore(const MemoryUserStore &) = delete;
    MemoryUserStore &operator=(const MemoryUserStore &) = delete;

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
     * @brief Remove all users from memory.
     */
    void clear();

    /**
     * @brief Return the number of stored users.
     *
     * @return User count.
     */
    [[nodiscard]] std::size_t size() const;

    /**
     * @brief Return true when the store is empty.
     *
     * @return true if no users are stored.
     */
    [[nodiscard]] bool empty() const;

  private:
    [[nodiscard]] static std::string key(std::string_view value);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, User> users_by_id_;
    std::unordered_map<std::string, std::string> id_by_email_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_STORES_MEMORYUSERSTORE_HPP_INCLUDED
