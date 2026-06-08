/**
 *
 *  @file MemoryUserStore.cpp
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

#include <rix/auth/stores/MemoryUserStore.hpp>

#include <utility>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] AuthError invalid_user_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidInput,
          "User is invalid.");
    }

    [[nodiscard]] AuthError empty_id_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidInput,
          "User id cannot be empty.");
    }

    [[nodiscard]] AuthError empty_email_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidEmail,
          "User email cannot be empty.");
    }

    [[nodiscard]] AuthError user_not_found_error()
    {
      return make_auth_error(
          AuthErrorCode::UserNotFound,
          "User not found.");
    }

    [[nodiscard]] AuthError user_already_exists_error()
    {
      return make_auth_error(
          AuthErrorCode::UserAlreadyExists,
          "User already exists.");
    }
  } // namespace

  AuthStatus MemoryUserStore::create(const User &user)
  {
    if (!user.valid())
    {
      return AuthStatus::failure(invalid_user_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(user.id());
    const std::string email_key = key(user.email());

    if (users_by_id_.find(id_key) != users_by_id_.end())
    {
      return AuthStatus::failure(user_already_exists_error());
    }

    if (id_by_email_.find(email_key) != id_by_email_.end())
    {
      return AuthStatus::failure(user_already_exists_error());
    }

    users_by_id_.emplace(id_key, user);
    id_by_email_.emplace(email_key, id_key);

    return AuthStatus::success();
  }

  AuthStatus MemoryUserStore::update(const User &user)
  {
    if (!user.valid())
    {
      return AuthStatus::failure(invalid_user_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(user.id());
    const auto existing = users_by_id_.find(id_key);

    if (existing == users_by_id_.end())
    {
      return AuthStatus::failure(user_not_found_error());
    }

    const std::string old_email_key = key(existing->second.email());
    const std::string new_email_key = key(user.email());

    const auto email_owner = id_by_email_.find(new_email_key);

    if (email_owner != id_by_email_.end() && email_owner->second != id_key)
    {
      return AuthStatus::failure(user_already_exists_error());
    }

    id_by_email_.erase(old_email_key);
    id_by_email_[new_email_key] = id_key;
    existing->second = user;

    return AuthStatus::success();
  }

  AuthStatus MemoryUserStore::remove_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_id_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(id);
    const auto existing = users_by_id_.find(id_key);

    if (existing == users_by_id_.end())
    {
      return AuthStatus::failure(user_not_found_error());
    }

    id_by_email_.erase(key(existing->second.email()));
    users_by_id_.erase(existing);

    return AuthStatus::success();
  }

  AuthResult<std::optional<User>>
  MemoryUserStore::find_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<std::optional<User>>::failure(empty_id_error());
    }

    std::lock_guard lock(mutex_);

    const auto it = users_by_id_.find(key(id));

    if (it == users_by_id_.end())
    {
      return AuthResult<std::optional<User>>::success(std::nullopt);
    }

    return AuthResult<std::optional<User>>::success(it->second);
  }

  AuthResult<std::optional<User>>
  MemoryUserStore::find_by_email(std::string_view email) const
  {
    if (email.empty())
    {
      return AuthResult<std::optional<User>>::failure(empty_email_error());
    }

    std::lock_guard lock(mutex_);

    const auto email_it = id_by_email_.find(key(email));

    if (email_it == id_by_email_.end())
    {
      return AuthResult<std::optional<User>>::success(std::nullopt);
    }

    const auto user_it = users_by_id_.find(email_it->second);

    if (user_it == users_by_id_.end())
    {
      return AuthResult<std::optional<User>>::success(std::nullopt);
    }

    return AuthResult<std::optional<User>>::success(user_it->second);
  }

  AuthResult<bool>
  MemoryUserStore::exists_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<bool>::failure(empty_id_error());
    }

    std::lock_guard lock(mutex_);

    return AuthResult<bool>::success(
        users_by_id_.find(key(id)) != users_by_id_.end());
  }

  AuthResult<bool>
  MemoryUserStore::exists_by_email(std::string_view email) const
  {
    if (email.empty())
    {
      return AuthResult<bool>::failure(empty_email_error());
    }

    std::lock_guard lock(mutex_);

    return AuthResult<bool>::success(
        id_by_email_.find(key(email)) != id_by_email_.end());
  }

  AuthResult<std::vector<User>> MemoryUserStore::all() const
  {
    std::lock_guard lock(mutex_);

    std::vector<User> users;
    users.reserve(users_by_id_.size());

    for (const auto &[id, user] : users_by_id_)
    {
      (void)id;
      users.push_back(user);
    }

    return AuthResult<std::vector<User>>::success(std::move(users));
  }

  void MemoryUserStore::clear()
  {
    std::lock_guard lock(mutex_);

    users_by_id_.clear();
    id_by_email_.clear();
  }

  std::size_t MemoryUserStore::size() const
  {
    std::lock_guard lock(mutex_);

    return users_by_id_.size();
  }

  bool MemoryUserStore::empty() const
  {
    return size() == 0;
  }

  std::string MemoryUserStore::key(std::string_view value)
  {
    return std::string(value);
  }
} // namespace rixlib::auth
