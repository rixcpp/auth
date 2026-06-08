/**
 *
 *  @file User.hpp
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
 *  User model for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_USER_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_USER_HPP_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Represents an authenticated application user.
   *
   * User is a simple value object used by rix/auth to represent the identity
   * stored in the user store.
   *
   * It intentionally does not expose password hashes through public setters
   * used by application code. The authentication service is responsible for
   * creating and verifying password hashes.
   */
  class User
  {
  public:
    /**
     * @brief Construct an empty user.
     */
    User() = default;

    /**
     * @brief Construct a user.
     *
     * @param id Stable user identifier.
     * @param email User email address.
     * @param password_hash Stored password hash.
     * @param created_at Unix timestamp in seconds.
     */
    User(std::string id,
         std::string email,
         std::string password_hash,
         std::int64_t created_at);

    /**
     * @brief Return the stable user identifier.
     *
     * @return User identifier.
     */
    [[nodiscard]] const std::string &id() const noexcept;

    /**
     * @brief Set the stable user identifier.
     *
     * @param value User identifier.
     */
    void set_id(std::string value);

    /**
     * @brief Return the user email address.
     *
     * @return User email address.
     */
    [[nodiscard]] const std::string &email() const noexcept;

    /**
     * @brief Set the user email address.
     *
     * @param value User email address.
     */
    void set_email(std::string value);

    /**
     * @brief Return the stored password hash.
     *
     * This value must never be sent to clients or logs.
     *
     * @return Stored password hash.
     */
    [[nodiscard]] const std::string &password_hash() const noexcept;

    /**
     * @brief Set the stored password hash.
     *
     * This function is intended for internal auth/store code.
     *
     * @param value Stored password hash.
     */
    void set_password_hash(std::string value);

    /**
     * @brief Return whether the user email address has been verified.
     *
     * @return true if the email is verified.
     */
    [[nodiscard]] bool email_verified() const noexcept;

    /**
     * @brief Set whether the user email address has been verified.
     *
     * @param value true when the email is verified.
     */
    void set_email_verified(bool value) noexcept;

    /**
     * @brief Return whether the user is active.
     *
     * Inactive users cannot authenticate.
     *
     * @return true if the user is active.
     */
    [[nodiscard]] bool active() const noexcept;

    /**
     * @brief Set whether the user is active.
     *
     * @param value true when the user is active.
     */
    void set_active(bool value) noexcept;

    /**
     * @brief Return the user creation timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t created_at() const noexcept;

    /**
     * @brief Set the user creation timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_created_at(std::int64_t value) noexcept;

    /**
     * @brief Return the last update timestamp.
     *
     * @return Unix timestamp in seconds.
     */
    [[nodiscard]] std::int64_t updated_at() const noexcept;

    /**
     * @brief Set the last update timestamp.
     *
     * @param value Unix timestamp in seconds.
     */
    void set_updated_at(std::int64_t value) noexcept;

    /**
     * @brief Return true when the user has a non-empty id and email.
     *
     * @return true if the user has the minimum required identity fields.
     */
    [[nodiscard]] bool valid() const noexcept;

    /**
     * @brief Return true when the given email matches this user.
     *
     * @param value Email address to compare.
     * @return true if the email is identical.
     */
    [[nodiscard]] bool has_email(std::string_view value) const noexcept;

  private:
    std::string id_;
    std::string email_;
    std::string password_hash_;
    bool email_verified_ = false;
    bool active_ = true;
    std::int64_t created_at_ = 0;
    std::int64_t updated_at_ = 0;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_USER_HPP_INCLUDED
