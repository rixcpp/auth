/**
 *
 *  @file Auth.hpp
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

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED

#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthResult.hpp>
#include <rix/auth/PasswordHasher.hpp>
#include <rix/auth/Session.hpp>
#include <rix/auth/SessionStore.hpp>
#include <rix/auth/Token.hpp>
#include <rix/auth/User.hpp>
#include <rix/auth/UserStore.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Request used to register a new user.
   */
  struct RegisterRequest
  {
    /**
     * @brief User email address.
     */
    std::string email;

    /**
     * @brief Plain-text password.
     */
    std::string password;
  };

  /**
   * @brief Request used to authenticate an existing user.
   */
  struct LoginRequest
  {
    /**
     * @brief User email address.
     */
    std::string email;

    /**
     * @brief Plain-text password.
     */
    std::string password;
  };

  /**
   * @brief Result returned after a successful login.
   */
  struct LoginResult
  {
    /**
     * @brief Authenticated user.
     */
    User user;

    /**
     * @brief Created server-side session.
     */
    Session session;

    /**
     * @brief Short-lived token derived from the authenticated session.
     */
    Token token;
  };

  /**
   * @brief Main authentication facade.
   *
   * Auth provides the developer-facing API for registration, login,
   * session authentication, session refresh, and logout.
   *
   * It delegates:
   * - validation to Vix validation-style checks
   * - password hashing to PasswordHasher backed by vix::crypto
   * - persistence to UserStore and SessionStore
   * - time to Vix time-compatible epoch seconds
   * - secure ids to vix::crypto random bytes
   */
  class Auth
  {
  public:
    /**
     * @brief Construct an auth service with development defaults.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     */
    Auth(UserStore &users, SessionStore &sessions);

    /**
     * @brief Construct an auth service with custom configuration.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     * @param config Authentication configuration.
     */
    Auth(UserStore &users, SessionStore &sessions, AuthConfig config);

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

  private:
    [[nodiscard]] AuthStatus validate_register_request(
        const RegisterRequest &request) const;

    [[nodiscard]] AuthStatus validate_login_request(
        const LoginRequest &request) const;

    [[nodiscard]] AuthStatus validate_email(std::string_view email) const;

    [[nodiscard]] AuthStatus validate_password_for_register(
        std::string_view password) const;

    [[nodiscard]] std::int64_t now_seconds() const noexcept;

    [[nodiscard]] AuthResult<std::string> make_user_id() const;
    [[nodiscard]] AuthResult<std::string> make_session_id() const;
    [[nodiscard]] AuthResult<std::string> make_token_value() const;

    [[nodiscard]] AuthResult<std::string>
    make_secure_id(std::string_view prefix) const;

    [[nodiscard]] Token make_token_for_user(
        std::string user_id,
        std::int64_t now,
        std::string value) const;

    UserStore *users_ = nullptr;
    SessionStore *sessions_ = nullptr;

    AuthConfig config_;
    PasswordHasher password_hasher_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED
