/**
 *
 *  @file User.cpp
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

#include <rix/auth/User.hpp>

#include <utility>

namespace rixlib::auth
{
  User::User(std::string id,
             std::string email,
             std::string password_hash,
             std::int64_t created_at)
      : id_(std::move(id)),
        email_(std::move(email)),
        password_hash_(std::move(password_hash)),
        created_at_(created_at),
        updated_at_(created_at)
  {
  }

  const std::string &User::id() const noexcept
  {
    return id_;
  }

  void User::set_id(std::string value)
  {
    id_ = std::move(value);
  }

  const std::string &User::email() const noexcept
  {
    return email_;
  }

  void User::set_email(std::string value)
  {
    email_ = std::move(value);
  }

  const std::string &User::password_hash() const noexcept
  {
    return password_hash_;
  }

  void User::set_password_hash(std::string value)
  {
    password_hash_ = std::move(value);
  }

  bool User::email_verified() const noexcept
  {
    return email_verified_;
  }

  void User::set_email_verified(bool value) noexcept
  {
    email_verified_ = value;
  }

  bool User::active() const noexcept
  {
    return active_;
  }

  void User::set_active(bool value) noexcept
  {
    active_ = value;
  }

  std::int64_t User::created_at() const noexcept
  {
    return created_at_;
  }

  void User::set_created_at(std::int64_t value) noexcept
  {
    created_at_ = value;
  }

  std::int64_t User::updated_at() const noexcept
  {
    return updated_at_;
  }

  void User::set_updated_at(std::int64_t value) noexcept
  {
    updated_at_ = value;
  }

  bool User::valid() const noexcept
  {
    return !id_.empty() && !email_.empty();
  }

  bool User::has_email(std::string_view value) const noexcept
  {
    return email_ == value;
  }
} // namespace rixlib::auth
