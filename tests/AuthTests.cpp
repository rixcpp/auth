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

#include <algorithm>
#include <cassert>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
  class MemoryUserStore final : public rixlib::auth::UserStore
  {
  public:
    [[nodiscard]] rixlib::auth::AuthStatus create(
        const rixlib::auth::User &user) override
    {
      if (!user.valid())
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::InvalidInput,
                "User is invalid."));
      }

      const auto exists = std::any_of(
          users_.begin(),
          users_.end(),
          [&](const rixlib::auth::User &stored)
          {
            return stored.id() == user.id() || stored.email() == user.email();
          });

      if (exists)
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::UserAlreadyExists,
                "User already exists."));
      }

      users_.push_back(user);
      return rixlib::auth::AuthStatus::success();
    }

    [[nodiscard]] rixlib::auth::AuthStatus update(
        const rixlib::auth::User &user) override
    {
      for (rixlib::auth::User &stored : users_)
      {
        if (stored.id() == user.id())
        {
          stored = user;
          return rixlib::auth::AuthStatus::success();
        }
      }

      return rixlib::auth::AuthStatus::failure(
          rixlib::auth::make_auth_error(
              rixlib::auth::AuthErrorCode::UserNotFound,
              "User not found."));
    }

    [[nodiscard]] rixlib::auth::AuthStatus remove_by_id(
        std::string_view id) override
    {
      const auto old_size = users_.size();

      users_.erase(
          std::remove_if(
              users_.begin(),
              users_.end(),
              [&](const rixlib::auth::User &user)
              {
                return user.id() == id;
              }),
          users_.end());

      if (users_.size() == old_size)
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::UserNotFound,
                "User not found."));
      }

      return rixlib::auth::AuthStatus::success();
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>
    find_by_id(std::string_view id) const override
    {
      for (const rixlib::auth::User &user : users_)
      {
        if (user.id() == id)
        {
          return rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>::success(user);
        }
      }

      return rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>::success(std::nullopt);
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>
    find_by_email(std::string_view email) const override
    {
      for (const rixlib::auth::User &user : users_)
      {
        if (user.email() == email)
        {
          return rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>::success(user);
        }
      }

      return rixlib::auth::AuthResult<std::optional<rixlib::auth::User>>::success(std::nullopt);
    }

    [[nodiscard]] rixlib::auth::AuthResult<bool>
    exists_by_id(std::string_view id) const override
    {
      const auto exists = std::any_of(
          users_.begin(),
          users_.end(),
          [&](const rixlib::auth::User &user)
          {
            return user.id() == id;
          });

      return rixlib::auth::AuthResult<bool>::success(exists);
    }

    [[nodiscard]] rixlib::auth::AuthResult<bool>
    exists_by_email(std::string_view email) const override
    {
      const auto exists = std::any_of(
          users_.begin(),
          users_.end(),
          [&](const rixlib::auth::User &user)
          {
            return user.email() == email;
          });

      return rixlib::auth::AuthResult<bool>::success(exists);
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::vector<rixlib::auth::User>>
    all() const override
    {
      return rixlib::auth::AuthResult<std::vector<rixlib::auth::User>>::success(users_);
    }

  private:
    std::vector<rixlib::auth::User> users_;
  };

  class MemorySessionStore final : public rixlib::auth::SessionStore
  {
  public:
    [[nodiscard]] rixlib::auth::AuthStatus create(
        const rixlib::auth::Session &session) override
    {
      if (!session.valid())
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::InvalidInput,
                "Session is invalid."));
      }

      const auto exists = std::any_of(
          sessions_.begin(),
          sessions_.end(),
          [&](const rixlib::auth::Session &stored)
          {
            return stored.id() == session.id();
          });

      if (exists)
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::InvalidSession,
                "Session already exists."));
      }

      sessions_.push_back(session);
      return rixlib::auth::AuthStatus::success();
    }

    [[nodiscard]] rixlib::auth::AuthStatus update(
        const rixlib::auth::Session &session) override
    {
      for (rixlib::auth::Session &stored : sessions_)
      {
        if (stored.id() == session.id())
        {
          stored = session;
          return rixlib::auth::AuthStatus::success();
        }
      }

      return rixlib::auth::AuthStatus::failure(
          rixlib::auth::make_auth_error(
              rixlib::auth::AuthErrorCode::InvalidSession,
              "Session not found."));
    }

    [[nodiscard]] rixlib::auth::AuthStatus remove_by_id(
        std::string_view id) override
    {
      const auto old_size = sessions_.size();

      sessions_.erase(
          std::remove_if(
              sessions_.begin(),
              sessions_.end(),
              [&](const rixlib::auth::Session &session)
              {
                return session.id() == id;
              }),
          sessions_.end());

      if (sessions_.size() == old_size)
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::InvalidSession,
                "Session not found."));
      }

      return rixlib::auth::AuthStatus::success();
    }

    [[nodiscard]] rixlib::auth::AuthStatus revoke_by_id(
        std::string_view id) override
    {
      for (rixlib::auth::Session &session : sessions_)
      {
        if (session.id() == id)
        {
          session.set_revoked(true);
          return rixlib::auth::AuthStatus::success();
        }
      }

      return rixlib::auth::AuthStatus::failure(
          rixlib::auth::make_auth_error(
              rixlib::auth::AuthErrorCode::InvalidSession,
              "Session not found."));
    }

    [[nodiscard]] rixlib::auth::AuthStatus revoke_by_user_id(
        std::string_view user_id) override
    {
      bool changed = false;

      for (rixlib::auth::Session &session : sessions_)
      {
        if (session.user_id() == user_id)
        {
          session.set_revoked(true);
          changed = true;
        }
      }

      if (!changed)
      {
        return rixlib::auth::AuthStatus::failure(
            rixlib::auth::make_auth_error(
                rixlib::auth::AuthErrorCode::InvalidSession,
                "Session not found."));
      }

      return rixlib::auth::AuthStatus::success();
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::optional<rixlib::auth::Session>>
    find_by_id(std::string_view id) const override
    {
      for (const rixlib::auth::Session &session : sessions_)
      {
        if (session.id() == id)
        {
          return rixlib::auth::AuthResult<std::optional<rixlib::auth::Session>>::success(session);
        }
      }

      return rixlib::auth::AuthResult<std::optional<rixlib::auth::Session>>::success(std::nullopt);
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::vector<rixlib::auth::Session>>
    find_by_user_id(std::string_view user_id) const override
    {
      std::vector<rixlib::auth::Session> result;

      for (const rixlib::auth::Session &session : sessions_)
      {
        if (session.user_id() == user_id)
        {
          result.push_back(session);
        }
      }

      return rixlib::auth::AuthResult<std::vector<rixlib::auth::Session>>::success(result);
    }

    [[nodiscard]] rixlib::auth::AuthResult<bool>
    exists_by_id(std::string_view id) const override
    {
      const auto exists = std::any_of(
          sessions_.begin(),
          sessions_.end(),
          [&](const rixlib::auth::Session &session)
          {
            return session.id() == id;
          });

      return rixlib::auth::AuthResult<bool>::success(exists);
    }

    [[nodiscard]] rixlib::auth::AuthResult<std::vector<rixlib::auth::Session>>
    all() const override
    {
      return rixlib::auth::AuthResult<std::vector<rixlib::auth::Session>>::success(sessions_);
    }

  private:
    std::vector<rixlib::auth::Session> sessions_;
  };

  void test_register_user_creates_user()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto result = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    assert(result.ok());
    assert(result.value().valid());
    assert(result.value().email() == "ada@example.com");
    assert(!result.value().password_hash().empty());

    const auto exists = users.exists_by_email("ada@example.com");

    assert(exists.ok());
    assert(exists.value());
  }

  void test_register_user_rejects_invalid_email()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto result = auth.register_user(
        rixlib::auth::RegisterRequest{
            "invalid-email",
            "secret123"});

    assert(result.failed());
    assert(result.error().code() == rixlib::auth::AuthErrorCode::InvalidEmail);
  }

  void test_register_user_rejects_short_password()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto result = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "short"});

    assert(result.failed());
    assert(result.error().code() == rixlib::auth::AuthErrorCode::InvalidPassword);
  }

  void test_register_user_rejects_duplicate_email()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto first = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    const auto second = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    assert(first.ok());
    assert(second.failed());
    assert(second.error().code() == rixlib::auth::AuthErrorCode::UserAlreadyExists);
  }

  void test_login_creates_session()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto registered = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    const auto logged_in = auth.login(
        rixlib::auth::LoginRequest{
            "ada@example.com",
            "secret123"});

    assert(registered.ok());
    assert(logged_in.ok());
    assert(logged_in.value().user.email() == "ada@example.com");
    assert(logged_in.value().session.valid());
    assert(logged_in.value().session.user_id() == logged_in.value().user.id());
  }

  void test_login_rejects_wrong_password()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto registered = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    const auto logged_in = auth.login(
        rixlib::auth::LoginRequest{
            "ada@example.com",
            "wrong-password"});

    assert(registered.ok());
    assert(logged_in.failed());
    assert(logged_in.error().code() == rixlib::auth::AuthErrorCode::InvalidCredentials);
  }

  void test_authenticate_session_returns_session()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto registered = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    const auto logged_in = auth.login(
        rixlib::auth::LoginRequest{
            "ada@example.com",
            "secret123"});

    const auto authenticated = auth.authenticate_session(
        logged_in.value().session.id());

    assert(registered.ok());
    assert(logged_in.ok());
    assert(authenticated.ok());
    assert(authenticated.value().id() == logged_in.value().session.id());
  }

  void test_logout_revokes_session()
  {
    MemoryUserStore users;
    MemorySessionStore sessions;
    rixlib::auth::Auth auth{users, sessions};

    const auto registered = auth.register_user(
        rixlib::auth::RegisterRequest{
            "ada@example.com",
            "secret123"});

    const auto logged_in = auth.login(
        rixlib::auth::LoginRequest{
            "ada@example.com",
            "secret123"});

    const auto logout = auth.logout(logged_in.value().session.id());
    const auto authenticated = auth.authenticate_session(
        logged_in.value().session.id());

    assert(registered.ok());
    assert(logged_in.ok());
    assert(logout.ok());
    assert(authenticated.failed());
    assert(authenticated.error().code() == rixlib::auth::AuthErrorCode::InvalidSession);
  }
} // namespace

int main()
{
  test_register_user_creates_user();
  test_register_user_rejects_invalid_email();
  test_register_user_rejects_short_password();
  test_register_user_rejects_duplicate_email();
  test_login_creates_session();
  test_login_rejects_wrong_password();
  test_authenticate_session_returns_session();
  test_logout_revokes_session();

  return 0;
}
