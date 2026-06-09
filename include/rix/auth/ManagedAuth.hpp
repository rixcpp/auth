/**
 *
 *  @file ManagedAuth.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_MANAGEDAUTH_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_MANAGEDAUTH_HPP_INCLUDED

#include <rix/auth/Auth.hpp>
#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthResult.hpp>
#include <rix/auth/PasswordHasher.hpp>
#include <rix/auth/Session.hpp>
#include <rix/auth/SessionStore.hpp>
#include <rix/auth/Token.hpp>
#include <rix/auth/User.hpp>
#include <rix/auth/UserStore.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace rixlib::auth
{
  /**
   * @brief Owns auth stores and exposes the public Auth API.
   *
   * ManagedAuth is used by the high-level Rix facade for simple APIs such as:
   *
   * @code
   * auto auth = rix.auth.memory();
   * @endcode
   *
   * Auth itself keeps references to UserStore and SessionStore. ManagedAuth
   * safely owns those stores so the internal Auth object never points to
   * destroyed storage.
   */
  class ManagedAuth
  {
  public:
    /**
     * @brief Construct a managed auth service.
     *
     * @param users Owned user storage backend.
     * @param sessions Owned session storage backend.
     * @param config Authentication configuration.
     */
    ManagedAuth(
        std::unique_ptr<UserStore> users,
        std::unique_ptr<SessionStore> sessions,
        AuthConfig config);

    ManagedAuth(const ManagedAuth &) = delete;
    ManagedAuth &operator=(const ManagedAuth &) = delete;

    ManagedAuth(ManagedAuth &&other) noexcept;
    ManagedAuth &operator=(ManagedAuth &&other) noexcept;

    /**
     * @brief Register a new user.
     *
     * @param request Registration request.
     * @return AuthResult containing the created user on success.
     */
    [[nodiscard]] AuthResult<User>
    register_user(const RegisterRequest &request);

    /**
     * @brief Authenticate a user and create a session.
     *
     * @param request Login request.
     * @return AuthResult containing user, session, and token on success.
     */
    [[nodiscard]] AuthResult<LoginResult>
    login(const LoginRequest &request);

    /**
     * @brief Revoke a session.
     *
     * @param session_id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus logout(std::string_view session_id);

    /**
     * @brief Revoke all sessions for a user.
     *
     * @param user_id User identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus logout_user(std::string_view user_id);

    /**
     * @brief Find and validate a session.
     *
     * @param session_id Session identifier.
     * @return AuthResult containing the usable session.
     */
    [[nodiscard]] AuthResult<Session>
    authenticate_session(std::string_view session_id);

    /**
     * @brief Refresh a valid session.
     *
     * @param session_id Session identifier.
     * @return AuthResult containing the refreshed session.
     */
    [[nodiscard]] AuthResult<Session>
    refresh_session(std::string_view session_id);

    /**
     * @brief Create a short-lived token for a user.
     *
     * @param user_id User identifier.
     * @return AuthResult containing the generated token.
     */
    [[nodiscard]] AuthResult<Token>
    issue_token(std::string_view user_id);

    /**
     * @brief Return the current configuration.
     *
     * @return Authentication configuration.
     */
    [[nodiscard]] const AuthConfig &config() const noexcept;

    /**
     * @brief Return the password hasher.
     *
     * @return Password hasher.
     */
    [[nodiscard]] const PasswordHasher &password_hasher() const noexcept;

    /**
     * @brief Access the underlying Auth service.
     *
     * @return Auth service.
     */
    [[nodiscard]] Auth &service() noexcept;

    /**
     * @brief Access the underlying Auth service.
     *
     * @return Auth service.
     */
    [[nodiscard]] const Auth &service() const noexcept;

    /**
     * @brief Access the owned user store.
     *
     * @return User store.
     */
    [[nodiscard]] UserStore &users() noexcept;

    /**
     * @brief Access the owned user store.
     *
     * @return User store.
     */
    [[nodiscard]] const UserStore &users() const noexcept;

    /**
     * @brief Access the owned session store.
     *
     * @return Session store.
     */
    [[nodiscard]] SessionStore &sessions() noexcept;

    /**
     * @brief Access the owned session store.
     *
     * @return Session store.
     */
    [[nodiscard]] const SessionStore &sessions() const noexcept;

  private:
    void rebuild_service();

    std::unique_ptr<UserStore> users_;
    std::unique_ptr<SessionStore> sessions_;
    AuthConfig config_;
    std::unique_ptr<Auth> auth_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_MANAGEDAUTH_HPP_INCLUDED
