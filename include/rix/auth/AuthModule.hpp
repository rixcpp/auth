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
#include <rix/auth/AuthError.hpp>
#include <rix/auth/AuthResult.hpp>
#include <rix/auth/ManagedAuth.hpp>
#include <rix/auth/PasswordHasher.hpp>
#include <rix/auth/SessionStore.hpp>
#include <rix/auth/UserStore.hpp>
#include <rix/auth/Version.hpp>
#include <rix/auth/stores/DbSessionStore.hpp>
#include <rix/auth/stores/DbUserStore.hpp>
#include <rix/auth/stores/MemorySessionStore.hpp>
#include <rix/auth/stores/MemoryUserStore.hpp>

#include <memory>
#include <string>
#include <string_view>

#include <vix/db/Database.hpp>

namespace rixlib::auth
{
  /**
   * @brief Auth error helpers exposed through rix.auth.error.
   *
   * This module keeps public examples away from low-level namespace helpers.
   */
  class AuthErrorModule
  {
  public:
    /**
     * @brief Return a success auth error value.
     *
     * @return AuthError with AuthErrorCode::None.
     */
    [[nodiscard]] AuthError none() const;

    /**
     * @brief Create an auth error value.
     *
     * @param code Stable auth error code.
     * @param message Human-readable error message.
     * @return AuthError value.
     */
    [[nodiscard]] AuthError make(
        AuthErrorCode code,
        std::string message) const;

    /**
     * @brief Convert an auth error code to a stable string.
     *
     * @param code Auth error code.
     * @return Stable string representation.
     */
    [[nodiscard]] std::string_view to_string(
        AuthErrorCode code) const noexcept;

    /**
     * @brief Convert an auth error value to a stable string.
     *
     * @param error Auth error value.
     * @return Stable string representation.
     */
    [[nodiscard]] std::string_view to_string(
        const AuthError &error) const noexcept;

    /**
     * @brief Return true when the error is success.
     *
     * @param error Auth error value.
     * @return true if the error code is None.
     */
    [[nodiscard]] bool ok(const AuthError &error) const noexcept;

    /**
     * @brief Return true when the error is failure.
     *
     * @param error Auth error value.
     * @return true if the error code is not None.
     */
    [[nodiscard]] bool failed(const AuthError &error) const noexcept;

    /**
     * @brief Return true when the error has the given code.
     *
     * @param error Auth error value.
     * @param code Expected auth error code.
     * @return true if the code matches.
     */
    [[nodiscard]] bool is(
        const AuthError &error,
        AuthErrorCode code) const noexcept;
  };

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

    /**
     * @brief Return a development config with a custom minimum password length.
     *
     * @param min_length Minimum accepted password length.
     * @return Development AuthConfig.
     */
    [[nodiscard]] AuthConfig development_with_min_password_length(
        std::size_t min_length) const;

    /**
     * @brief Return a production config with a custom minimum password length.
     *
     * @param min_length Minimum accepted password length.
     * @return Production AuthConfig.
     */
    [[nodiscard]] AuthConfig production_with_min_password_length(
        std::size_t min_length) const;

    /**
     * @brief Return true when the config looks usable.
     *
     * This is intentionally conservative. It catches obvious configuration
     * mistakes before the user creates an auth service.
     *
     * @param config Auth configuration.
     * @return true if the configuration is accepted.
     */
    [[nodiscard]] bool valid(const AuthConfig &config) const noexcept;

    /**
     * @brief Validate an auth configuration.
     *
     * @param config Auth configuration.
     * @return AuthStatus indicating success or the first validation error.
     */
    [[nodiscard]] AuthStatus validate(const AuthConfig &config) const;
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
     * @brief Hash a plain-text password using the given auth config.
     *
     * @param password Plain-text password.
     * @param config Auth configuration.
     * @return Encoded password hash on success.
     */
    [[nodiscard]] AuthResult<std::string>
    hash(
        std::string_view password,
        const AuthConfig &config) const;

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
     * @brief Verify a password against an encoded password hash using config.
     *
     * @param password Plain-text password.
     * @param password_hash Encoded password hash.
     * @param config Auth configuration.
     * @return true when the password matches.
     */
    [[nodiscard]] bool verify(
        std::string_view password,
        std::string_view password_hash,
        const AuthConfig &config) const;

    /**
     * @brief Return true when the password satisfies default policy.
     *
     * @param password Plain-text password.
     * @return true if accepted.
     */
    [[nodiscard]] bool accepts(std::string_view password) const;

    /**
     * @brief Return true when the password satisfies the given config.
     *
     * @param password Plain-text password.
     * @param config Auth configuration.
     * @return true if accepted.
     */
    [[nodiscard]] bool accepts(
        std::string_view password,
        const AuthConfig &config) const;

    /**
     * @brief Return a new password hasher with default settings.
     *
     * @return PasswordHasher instance.
     */
    [[nodiscard]] PasswordHasher hasher() const;

    /**
     * @brief Return a new password hasher with the given config.
     *
     * @param config Auth configuration.
     * @return PasswordHasher instance.
     */
    [[nodiscard]] PasswordHasher hasher(const AuthConfig &config) const;
  };

  /**
   * @brief Store factory helpers exposed through rix.auth.stores.
   *
   * This allows advanced users to create stores without manually depending on
   * concrete store class names in public examples.
   */
  class AuthStoreModule
  {
  public:
    /**
     * @brief Create a memory user store.
     *
     * @return Memory user store.
     */
    [[nodiscard]] std::unique_ptr<UserStore> memory_users() const;

    /**
     * @brief Create a memory session store.
     *
     * @return Memory session store.
     */
    [[nodiscard]] std::unique_ptr<SessionStore> memory_sessions() const;

    /**
     * @brief Create a database user store.
     *
     * @param database Vix database facade.
     * @return Database user store.
     */
    [[nodiscard]] std::unique_ptr<UserStore>
    database_users(vix::db::Database &database) const;

    /**
     * @brief Create a database session store.
     *
     * @param database Vix database facade.
     * @return Database session store.
     */
    [[nodiscard]] std::unique_ptr<SessionStore>
    database_sessions(vix::db::Database &database) const;
  };

  /**
   * @brief High-level authentication facade exposed through rix.auth.
   *
   * AuthModule is the public entry point used by the global Rix facade.
   *
   * Public examples should prefer:
   *
   * @code
   * auto auth = rix.auth.memory();
   * auto auth = rix.auth.database(db);
   * @endcode
   *
   * Lower-level caller-owned store APIs are still available for advanced
   * integration, but managed APIs are the safer default.
   */
  class AuthModule
  {
  public:
    /**
     * @brief Error helpers.
     */
    AuthErrorModule error{};

    /**
     * @brief Configuration helpers.
     */
    AuthConfigModule config{};

    /**
     * @brief Password hashing helpers.
     */
    AuthPasswordModule password{};

    /**
     * @brief Store factory helpers.
     */
    AuthStoreModule stores{};

    /**
     * @brief Create an Auth service with caller-owned stores.
     *
     * This is an advanced API. The caller must guarantee that both stores
     * outlive the returned Auth service.
     *
     * Prefer memory(), database(), or managed() for public application code.
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
     * This is an advanced API. The caller must guarantee that both stores
     * outlive the returned Auth service.
     *
     * Prefer memory(), database(), or managed() for public application code.
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
     * @brief Create a managed auth service from owned stores.
     *
     * This is the safe custom-store API. The returned ManagedAuth owns the
     * stores and prevents dangling references.
     *
     * @param users Owned user storage backend.
     * @param sessions Owned session storage backend.
     * @return Managed auth service or configuration/store error.
     */
    [[nodiscard]] AuthResult<ManagedAuth> managed(
        std::unique_ptr<UserStore> users,
        std::unique_ptr<SessionStore> sessions) const;

    /**
     * @brief Create a managed auth service from owned stores and config.
     *
     * This is the safe custom-store API. The returned ManagedAuth owns the
     * stores and prevents dangling references.
     *
     * @param users Owned user storage backend.
     * @param sessions Owned session storage backend.
     * @param config Authentication configuration.
     * @return Managed auth service or configuration/store error.
     */
    [[nodiscard]] AuthResult<ManagedAuth> managed(
        std::unique_ptr<UserStore> users,
        std::unique_ptr<SessionStore> sessions,
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
