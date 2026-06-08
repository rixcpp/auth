/**
 *
 *  @file AuthTests.cpp
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

#include <rix/auth/Auth.hpp>
#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthError.hpp>
#include <rix/auth/stores/MemorySessionStore.hpp>
#include <rix/auth/stores/MemoryUserStore.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::Auth;
  using rixlib::auth::AuthConfig;
  using rixlib::auth::AuthErrorCode;
  using rixlib::auth::LoginRequest;
  using rixlib::auth::MemorySessionStore;
  using rixlib::auth::MemoryUserStore;
  using rixlib::auth::RegisterRequest;
  using rixlib::auth::User;

  [[nodiscard]] AuthConfig test_config()
  {
    AuthConfig config = AuthConfig::development();
    config.set_min_password_length(8);
    config.set_session_ttl_seconds(3600);
    config.set_token_ttl_seconds(600);
    config.set_issuer("rix/auth/tests");
    config.set_require_email_verification(false);
    config.set_rotate_sessions(true);
    return config;
  }

  struct AuthFixture
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    Auth auth;

    AuthFixture()
        : users(),
          sessions(),
          auth(users, sessions, test_config())
    {
    }
  };

  TEST(AuthTests, RegisterUserCreatesValidUser)
  {
    AuthFixture fixture;

    const auto result = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(result.ok());

    const User &user = result.value();

    EXPECT_TRUE(user.valid());
    EXPECT_FALSE(user.id().empty());
    EXPECT_EQ(user.email(), "ada@example.com");
    EXPECT_FALSE(user.password_hash().empty());
    EXPECT_NE(user.password_hash(), "correct-password");
    EXPECT_TRUE(user.email_verified());
    EXPECT_TRUE(user.active());
    EXPECT_GT(user.created_at(), 0);
    EXPECT_GT(user.updated_at(), 0);
    EXPECT_EQ(fixture.users.size(), 1);
  }

  TEST(AuthTests, RegisterUserPersistsUserInStore)
  {
    AuthFixture fixture;

    const auto registered = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(registered.ok());

    const auto found = fixture.users.find_by_email("ada@example.com");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());

    EXPECT_EQ(found.value()->id(), registered.value().id());
    EXPECT_EQ(found.value()->email(), "ada@example.com");
  }

  TEST(AuthTests, RegisterUserRejectsInvalidEmail)
  {
    AuthFixture fixture;

    const auto result = fixture.auth.register_user(
        RegisterRequest{
            "invalid-email",
            "correct-password"});

    ASSERT_TRUE(result.failed());
    EXPECT_EQ(result.error().code(), AuthErrorCode::InvalidEmail);
    EXPECT_TRUE(fixture.users.empty());
  }

  TEST(AuthTests, RegisterUserRejectsEmptyEmail)
  {
    AuthFixture fixture;

    const auto result = fixture.auth.register_user(
        RegisterRequest{
            "",
            "correct-password"});

    ASSERT_TRUE(result.failed());
    EXPECT_EQ(result.error().code(), AuthErrorCode::InvalidEmail);
    EXPECT_TRUE(fixture.users.empty());
  }

  TEST(AuthTests, RegisterUserRejectsWeakPassword)
  {
    AuthFixture fixture;

    const auto result = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "short"});

    ASSERT_TRUE(result.failed());
    EXPECT_EQ(result.error().code(), AuthErrorCode::InvalidPassword);
    EXPECT_TRUE(fixture.users.empty());
  }

  TEST(AuthTests, RegisterUserRejectsDuplicateEmail)
  {
    AuthFixture fixture;

    const auto first = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(first.ok());

    const auto second = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "another-password"});

    ASSERT_TRUE(second.failed());
    EXPECT_EQ(second.error().code(), AuthErrorCode::UserAlreadyExists);
    EXPECT_EQ(fixture.users.size(), 1);
  }

  TEST(AuthTests, RegisterUserHonorsEmailVerificationConfig)
  {
    MemoryUserStore users;
    MemorySessionStore sessions;

    AuthConfig config = test_config();
    config.set_require_email_verification(true);

    Auth auth{users, sessions, config};

    const auto result = auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(result.ok());
    EXPECT_FALSE(result.value().email_verified());
  }

  TEST(AuthTests, LoginCreatesSessionAndToken)
  {
    AuthFixture fixture;

    const auto registered = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(registered.ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    EXPECT_EQ(logged_in.value().user.email(), "ada@example.com");

    EXPECT_TRUE(logged_in.value().session.valid());
    EXPECT_FALSE(logged_in.value().session.id().empty());
    EXPECT_EQ(logged_in.value().session.user_id(), registered.value().id());
    EXPECT_FALSE(logged_in.value().session.revoked());
    EXPECT_GT(logged_in.value().session.created_at(), 0);
    EXPECT_GT(logged_in.value().session.expires_at(),
              logged_in.value().session.created_at());

    EXPECT_TRUE(logged_in.value().token.valid());
    EXPECT_FALSE(logged_in.value().token.value().empty());
    EXPECT_EQ(logged_in.value().token.user_id(), registered.value().id());
    EXPECT_EQ(logged_in.value().token.issuer(), "rix/auth/tests");
    EXPECT_GT(logged_in.value().token.issued_at(), 0);
    EXPECT_GT(logged_in.value().token.expires_at(),
              logged_in.value().token.issued_at());

    EXPECT_EQ(fixture.sessions.size(), 1);
  }

  TEST(AuthTests, LoginStoresCreatedSession)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    const auto stored = fixture.sessions.find_by_id(
        logged_in.value().session.id());

    ASSERT_TRUE(stored.ok());
    ASSERT_TRUE(stored.value().has_value());

    EXPECT_EQ(stored.value()->id(), logged_in.value().session.id());
    EXPECT_EQ(stored.value()->user_id(), logged_in.value().user.id());
  }

  TEST(AuthTests, LoginRejectsUnknownUserWithInvalidCredentials)
  {
    AuthFixture fixture;

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "missing@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidCredentials);
    EXPECT_TRUE(fixture.sessions.empty());
  }

  TEST(AuthTests, LoginRejectsWrongPasswordWithInvalidCredentials)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "wrong-password"});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidCredentials);
    EXPECT_TRUE(fixture.sessions.empty());
  }

  TEST(AuthTests, LoginRejectsInvalidEmail)
  {
    AuthFixture fixture;

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "invalid-email",
            "correct-password"});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidEmail);
  }

  TEST(AuthTests, LoginRejectsEmptyPassword)
  {
    AuthFixture fixture;

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            ""});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidPassword);
  }

  TEST(AuthTests, LoginRejectsInactiveUser)
  {
    AuthFixture fixture;

    const auto registered = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(registered.ok());

    User user = registered.value();
    user.set_active(false);

    ASSERT_TRUE(fixture.users.update(user).ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidCredentials);
  }

  TEST(AuthTests, LoginRejectsUnverifiedUserWhenVerificationIsRequired)
  {
    MemoryUserStore users;
    MemorySessionStore sessions;

    AuthConfig config = test_config();
    config.set_require_email_verification(true);

    Auth auth{users, sessions, config};

    const auto registered = auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(registered.ok());
    EXPECT_FALSE(registered.value().email_verified());

    const auto logged_in = auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.failed());
    EXPECT_EQ(logged_in.error().code(), AuthErrorCode::InvalidState);
  }

  TEST(AuthTests, AuthenticateSessionReturnsUsableSession)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    const auto authenticated = fixture.auth.authenticate_session(
        logged_in.value().session.id());

    ASSERT_TRUE(authenticated.ok());
    EXPECT_EQ(authenticated.value().id(), logged_in.value().session.id());
    EXPECT_FALSE(authenticated.value().revoked());
  }

  TEST(AuthTests, AuthenticateSessionRejectsEmptySessionId)
  {
    AuthFixture fixture;

    const auto authenticated = fixture.auth.authenticate_session("");

    ASSERT_TRUE(authenticated.failed());
    EXPECT_EQ(authenticated.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(AuthTests, AuthenticateSessionRejectsMissingSession)
  {
    AuthFixture fixture;

    const auto authenticated = fixture.auth.authenticate_session("missing");

    ASSERT_TRUE(authenticated.failed());
    EXPECT_EQ(authenticated.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(AuthTests, AuthenticateSessionRejectsRevokedSession)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    ASSERT_TRUE(fixture.auth.logout(logged_in.value().session.id()).ok());

    const auto authenticated = fixture.auth.authenticate_session(
        logged_in.value().session.id());

    ASSERT_TRUE(authenticated.failed());
    EXPECT_EQ(authenticated.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(AuthTests, AuthenticateSessionRejectsExpiredSession)
  {
    MemoryUserStore users;
    MemorySessionStore sessions;

    AuthConfig config = test_config();
    config.set_session_ttl_seconds(-1);

    Auth auth{users, sessions, config};

    ASSERT_TRUE(auth.register_user(
                        RegisterRequest{
                            "ada@example.com",
                            "correct-password"})
                    .ok());

    const auto logged_in = auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    const auto authenticated = auth.authenticate_session(
        logged_in.value().session.id());

    ASSERT_TRUE(authenticated.failed());
    EXPECT_EQ(authenticated.error().code(), AuthErrorCode::SessionExpired);
  }

  TEST(AuthTests, LogoutRevokesSession)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    const auto status = fixture.auth.logout(
        logged_in.value().session.id());

    ASSERT_TRUE(status.ok());

    const auto stored = fixture.sessions.find_by_id(
        logged_in.value().session.id());

    ASSERT_TRUE(stored.ok());
    ASSERT_TRUE(stored.value().has_value());
    EXPECT_TRUE(stored.value()->revoked());
  }

  TEST(AuthTests, LogoutRejectsEmptySessionId)
  {
    AuthFixture fixture;

    const auto status = fixture.auth.logout("");

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(AuthTests, LogoutUserRevokesAllUserSessions)
  {
    AuthFixture fixture;

    const auto registered = fixture.auth.register_user(
        RegisterRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(registered.ok());

    const auto first = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    const auto second = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());

    const auto status = fixture.auth.logout_user(registered.value().id());

    ASSERT_TRUE(status.ok());

    const auto sessions = fixture.sessions.find_by_user_id(
        registered.value().id());

    ASSERT_TRUE(sessions.ok());
    ASSERT_EQ(sessions.value().size(), 2);

    for (const auto &session : sessions.value())
    {
      EXPECT_TRUE(session.revoked());
    }
  }

  TEST(AuthTests, LogoutUserRejectsEmptyUserId)
  {
    AuthFixture fixture;

    const auto status = fixture.auth.logout_user("");

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidInput);
  }

  TEST(AuthTests, RefreshSessionExtendsExpiration)
  {
    AuthFixture fixture;

    ASSERT_TRUE(fixture.auth.register_user(
                                RegisterRequest{
                                    "ada@example.com",
                                    "correct-password"})
                    .ok());

    const auto logged_in = fixture.auth.login(
        LoginRequest{
            "ada@example.com",
            "correct-password"});

    ASSERT_TRUE(logged_in.ok());

    const auto refreshed = fixture.auth.refresh_session(
        logged_in.value().session.id());

    ASSERT_TRUE(refreshed.ok());

    EXPECT_EQ(refreshed.value().id(), logged_in.value().session.id());
    EXPECT_GE(refreshed.value().expires_at(),
              logged_in.value().session.expires_at());
    EXPECT_GE(refreshed.value().last_seen_at(),
              logged_in.value().session.last_seen_at());
  }

  TEST(AuthTests, RefreshSessionRejectsMissingSession)
  {
    AuthFixture fixture;

    const auto refreshed = fixture.auth.refresh_session("missing");

    ASSERT_TRUE(refreshed.failed());
    EXPECT_EQ(refreshed.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(AuthTests, IssueTokenCreatesUsableToken)
  {
    AuthFixture fixture;

    const auto token = fixture.auth.issue_token("user_1");

    ASSERT_TRUE(token.ok());

    EXPECT_TRUE(token.value().valid());
    EXPECT_FALSE(token.value().value().empty());
    EXPECT_EQ(token.value().user_id(), "user_1");
    EXPECT_EQ(token.value().issuer(), "rix/auth/tests");
    EXPECT_FALSE(token.value().revoked());
    EXPECT_GT(token.value().issued_at(), 0);
    EXPECT_GT(token.value().expires_at(), token.value().issued_at());
  }

  TEST(AuthTests, IssueTokenRejectsEmptyUserId)
  {
    AuthFixture fixture;

    const auto token = fixture.auth.issue_token("");

    ASSERT_TRUE(token.failed());
    EXPECT_EQ(token.error().code(), AuthErrorCode::InvalidInput);
  }

  TEST(AuthTests, ConfigReturnsConfiguredValues)
  {
    AuthFixture fixture;

    EXPECT_EQ(fixture.auth.config().min_password_length(), 8);
    EXPECT_EQ(fixture.auth.config().session_ttl_seconds(), 3600);
    EXPECT_EQ(fixture.auth.config().token_ttl_seconds(), 600);
    EXPECT_EQ(fixture.auth.config().issuer(), "rix/auth/tests");
    EXPECT_FALSE(fixture.auth.config().require_email_verification());
    EXPECT_TRUE(fixture.auth.config().rotate_sessions());
  }

  TEST(AuthTests, PasswordHasherUsesAuthConfiguration)
  {
    MemoryUserStore users;
    MemorySessionStore sessions;

    AuthConfig config = test_config();
    config.set_min_password_length(16);

    Auth auth{users, sessions, config};

    EXPECT_FALSE(auth.password_hasher().accepts("short-password"));
    EXPECT_TRUE(auth.password_hasher().accepts("very-strong-password"));
  }
} // namespace
