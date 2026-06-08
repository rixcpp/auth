/**
 *
 *  @file basic.cpp
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
#include <iostream>
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
            return stored.id() == user.id() ||
                   stored.email() == user.email();
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

  void print_error(const rixlib::auth::AuthError &error)
  {
    std::cout << "error: " << rixlib::auth::to_string(error.code())
              << " - " << error.message() << '\n';
  }
} // namespace

int main()
{
  MemoryUserStore users;
  MemorySessionStore sessions;

  rixlib::auth::Auth auth{users, sessions};

  const auto registered = auth.register_user(
      rixlib::auth::RegisterRequest{
          "ada@example.com",
          "secret123"});

  if (registered.failed())
  {
    print_error(registered.error());
    return 1;
  }

  std::cout << "registered user: " << registered.value().email() << '\n';

  const auto logged_in = auth.login(
      rixlib::auth::LoginRequest{
          "ada@example.com",
          "secret123"});

  if (logged_in.failed())
  {
    print_error(logged_in.error());
    return 1;
  }

  std::cout << "logged in user: " << logged_in.value().user.email() << '\n';
  std::cout << "session id: " << logged_in.value().session.id() << '\n';

  const auto authenticated = auth.authenticate_session(
      logged_in.value().session.id());

  if (authenticated.failed())
  {
    print_error(authenticated.error());
    return 1;
  }

  std::cout << "session authenticated for user id: "
            << authenticated.value().user_id() << '\n';

  const auto logout = auth.logout(logged_in.value().session.id());

  if (logout.failed())
  {
    print_error(logout.error());
    return 1;
  }

  std::cout << "logged out successfully\n";

  return 0;
}
