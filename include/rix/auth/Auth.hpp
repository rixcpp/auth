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
 *  Main authentication facade for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED

#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthResult.hpp>
#include <rix/auth/PasswordHasher.hpp>
#include <rix/auth/Session.hpp>
#include <rix/auth/SessionStore.hpp>
#include <rix/auth/User.hpp>
#include <rix/auth/UserStore.hpp>

#include <string>
#include <string_view>

namespace rixlib::auth
{
  /**
   * @brief Request used to register a new user.
   *
   * RegisterRequest keeps the public API simple for developers while Auth
   * handles validation, hashing, user creation, and store interaction.
   */
  struct RegisterRequest
  {
    /**
     * @brief User email address.
     */
    std::string email;

    /**
     * @brief Plain-text password.
     *
     * This value is only accepted as input. It must never be stored directly.
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
     * @brief Created authenticated session.
     */
    Session session;
  };

  /**
   * @brief Main rix/auth facade.
   *
   * Auth exposes a simple developer-facing API for common authentication
   * operations such as register, login, session validation, and logout.
   *
   * The complexity stays behind this class:
   *
   * - input validation
   * - password hashing
   * - session creation
   * - store access
   * - error mapping
   *
   * The application only provides stores and calls clear methods.
   */
  class Auth
  {
  public:
    /**
     * @brief Construct an authentication service.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     */
    Auth(UserStore &users, SessionStore &sessions);

    /**
     * @brief Construct an authentication service with custom configuration.
     *
     * @param users User storage backend.
     * @param sessions Session storage backend.
     * @param config Authentication configuration.
     */
    Auth(UserStore &users, SessionStore &sessions, AuthConfig config);

    /**
     * @brief Register a new user.
     *
     * This method validates the email and password, checks if the user already
     * exists, hashes the password, creates the user, and stores it.
     *
     * @param request Registration request.
     * @return AuthResult containing the created user on success.
     */
    [[nodiscard]] AuthResult<User> register_user(const RegisterRequest &request);

    /**
     * @brief Authenticate a user and create a session.
     *
     * This method validates credentials, verifies the password, creates a
     * session, and stores it.
     *
     * @param request Login request.
     * @return AuthResult containing the authenticated user and session.
     */
    [[nodiscard]] AuthResult<LoginResult> login(const LoginRequest &request);

    /**
     * @brief Revoke a session.
     *
     * @param session_id Session identifier.
     * @return AuthStatus indicating success or failure.
     */
    [[nodiscard]] AuthStatus logout(std::string_view session_id);

    /**
     * @brief Find and validate a session.
     *
     * @param session_id Session identifier.
     * @return AuthResult containing the usable session when valid.
     */
    [[nodiscard]] AuthResult<Session> authenticate_session(std::string_view session_id);

    /**
     * @brief Return the current authentication configuration.
     *
     * @return Authentication configuration.
     */
    [[nodiscard]] const AuthConfig &config() const noexcept;

    /**
     * @brief Return the password hasher used by this auth service.
     *
     * @return Password hasher.
     */
    [[nodiscard]] const PasswordHasher &password_hasher() const noexcept;

  private:
    [[nodiscard]] AuthStatus validate_register_request(
        const RegisterRequest &request) const;

    [[nodiscard]] AuthStatus validate_login_request(
        const LoginRequest &request) const;

    [[nodiscard]] bool is_valid_email(std::string_view email) const noexcept;

    [[nodiscard]] std::string make_user_id() const;

    [[nodiscard]] std::string make_session_id() const;

    [[nodiscard]] std::int64_t now_seconds() const noexcept;

    UserStore *users_ = nullptr;
    SessionStore *sessions_ = nullptr;
    AuthConfig config_;
    PasswordHasher password_hasher_;
  };
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_AUTH_HPP_INCLUDED
