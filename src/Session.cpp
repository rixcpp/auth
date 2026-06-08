/**
 *
 *  @file Session.cpp
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

#include <rix/auth/Session.hpp>

#include <utility>

namespace rixlib::auth
{
  Session::Session(std::string id,
                   std::string user_id,
                   std::int64_t created_at,
                   std::int64_t expires_at)
      : id_(std::move(id)),
        user_id_(std::move(user_id)),
        created_at_(created_at),
        expires_at_(expires_at),
        last_seen_at_(created_at)
  {
  }

  const std::string &Session::id() const noexcept
  {
    return id_;
  }

  void Session::set_id(std::string value)
  {
    id_ = std::move(value);
  }

  const std::string &Session::user_id() const noexcept
  {
    return user_id_;
  }

  void Session::set_user_id(std::string value)
  {
    user_id_ = std::move(value);
  }

  std::int64_t Session::created_at() const noexcept
  {
    return created_at_;
  }

  void Session::set_created_at(std::int64_t value) noexcept
  {
    created_at_ = value;
  }

  std::int64_t Session::expires_at() const noexcept
  {
    return expires_at_;
  }

  void Session::set_expires_at(std::int64_t value) noexcept
  {
    expires_at_ = value;
  }

  std::int64_t Session::last_seen_at() const noexcept
  {
    return last_seen_at_;
  }

  void Session::set_last_seen_at(std::int64_t value) noexcept
  {
    last_seen_at_ = value;
  }

  bool Session::revoked() const noexcept
  {
    return revoked_;
  }

  void Session::set_revoked(bool value) noexcept
  {
    revoked_ = value;
  }

  bool Session::valid() const noexcept
  {
    return !id_.empty() && !user_id_.empty();
  }

  bool Session::has_id() const noexcept
  {
    return !id_.empty();
  }

  bool Session::has_user_id() const noexcept
  {
    return !user_id_.empty();
  }

  bool Session::has_id(std::string_view value) const noexcept
  {
    return id_ == value;
  }

  bool Session::belongs_to(std::string_view value) const noexcept
  {
    return user_id_ == value;
  }

  bool Session::expired(std::int64_t now) const noexcept
  {
    return expires_at_ > 0 && now >= expires_at_;
  }

  bool Session::usable(std::int64_t now) const noexcept
  {
    return valid() && !revoked_ && !expired(now);
  }

  bool Session::refreshable(std::int64_t now) const noexcept
  {
    return usable(now);
  }

  void Session::refresh(std::int64_t now, std::int64_t ttl_seconds) noexcept
  {
    last_seen_at_ = now;
    expires_at_ = now + ttl_seconds;
  }

  void Session::revoke() noexcept
  {
    revoked_ = true;
  }
} // namespace rixlib::auth
