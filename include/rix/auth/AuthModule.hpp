/**
 *
 *  @file AuthModule.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHMODULE_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHMODULE_HPP_INCLUDED

#include <rix/auth/Auth.hpp>
#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/ManagedAuth.hpp>
#include <rix/auth/PasswordHasher.hpp>
#include <rix/auth/SessionStore.hpp>
#include <rix/auth/UserStore.hpp>
#include <rix/auth/Version.hpp>
#include <rix/auth/stores/DbSessionStore.hpp>
#include <rix/auth/stores/DbUserStore.hpp>
#include <rix/auth/stores/MemorySessionStore.hpp>
#include <rix/auth/stores/MemoryUserStore.hpp>

#include <string>

#include <vix/db/Database.hpp>

namespace rixlib::auth
{
  /**
   * @brief Auth configuration facade exposed through rix.auth.config.
   */
  class AuthConfigModule
  {
  public:
    /**
     * @brief Return the default development auth configuration.
     *
     * @return Development AuthConfig.
     */
    [[nodiscard]] AuthConfig development() const;

    /**
     * @brief Return the default production auth configuration.
     *
     * @return Production AuthConfig.
     */
    [[nodiscard]] AuthConfig production() const;
  };

  /**
   * @brief Password helper facade exposed through rix.auth.password.
   */
  class AuthPasswordModule
  {
  public:
    /**
     * @brief Hash a plain-text password using the default hasher.
     *
     * @param password Plain-text password.
     * @return Encoded password hash on success.
     */
    [[nodiscard]] AuthResult<std::string>
    hash(std::string_view password) const;

    /**
     * @brief Verify a password against an encoded password hash.
     *
     * @param password Plain-text password.
     * @param password_hash Encoded password hash.
     * @return true when the password matches.
     */
    [[nodiscard]] bool verify(
        std::string_view password,
        std::string_view password_hash) const;

    /**
     * @brief Return a new password hasher with default settings.
     *
     * @return PasswordHasher instance.
     */
    [[nodiscard]] PasswordHasher hasher() const;
  };

  /**
   * @brief High-level authentication facade exposed through rix.auth.
   *
   * AuthModule is the simple public entry point used by the global Rix facade.
   * It can create memory-backed auth services for examples and tests,
   * database-backed auth services for durable applications, or Auth services
   * from custom stores.
   */
  class AuthModule
  {
  public:
    /**
     * @brief Configuration helpers.
     */
    AuthConfigModule config{};

    /**
     * @brief Password hashing helpers.
     */
    AuthPasswordModule password{};

    /**
     * @brief Create an Auth service with caller-owned stores.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     * @return Auth service using development defaults.
     */
    [[nodiscard]] Auth create(
        UserStore &users,
        SessionStore &sessions) const;

    /**
     * @brief Create an Auth service with caller-owned stores and config.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     * @param config Authentication configuration.
     * @return Auth service.
     */
    [[nodiscard]] Auth create(
        UserStore &users,
        SessionStore &sessions,
        AuthConfig config) const;

    /**
     * @brief Create a memory-backed managed Auth service.
     *
     * @return Managed auth service using development defaults.
     */
    [[nodiscard]] ManagedAuth memory() const;

    /**
     * @brief Create a memory-backed managed Auth service with config.
     *
     * @param config Authentication configuration.
     * @return Managed auth service.
     */
    [[nodiscard]] ManagedAuth memory(AuthConfig config) const;

    /**
     * @brief Create a database-backed managed Auth service.
     *
     * @param database Vix database facade.
     * @return Managed auth service using production defaults.
     */
    [[nodiscard]] ManagedAuth database(vix::db::Database &database) const;

    /**
     * @brief Create a database-backed managed Auth service with config.
     *
     * @param database Vix database facade.
     * @param config Authentication configuration.
     * @return Managed auth service.
     */
    [[nodiscard]] ManagedAuth database(
        vix::db::Database &database,
        AuthConfig config) const;

    /**
     * @brief Return the package version string.
     *
     * @return Version string.
     */
    [[nodiscard]] std::string version() const;

    /**
     * @brief Return the package major version.
     *
     * @return Major version.
     */
    [[nodiscard]] int version_major() const noexcept;

    /**
     * @brief Return the package minor version.
     *
     * @return Minor version.
     */
    [[nodiscard]] int version_minor() const noexcept;

    /**
     * @brief Return the package patch version.
     *
     * @return Patch version.
     */
    [[nodiscard]] int version_patch() const noexcept;

    /**
     * @brief Return the encoded package version number.
     *
     * @return Encoded version.
     */
    [[nodiscard]] int version_number() const noexcept;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTHMODULE_HPP_INCLUDED
