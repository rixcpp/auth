/**
 *
 *  @file Token.cpp
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

#include <rix/auth/Token.hpp>

#include <utility>

namespace rixlib::auth
{
  Token::Token(std::string value,
               std::string user_id,
               std::int64_t issued_at,
               std::int64_t expires_at)
      : value_(std::move(value)),
        user_id_(std::move(user_id)),
        issued_at_(issued_at),
        expires_at_(expires_at)
  {
  }

  const std::string &Token::value() const noexcept
  {
    return value_;
  }

  void Token::set_value(std::string value)
  {
    value_ = std::move(value);
  }

  const std::string &Token::user_id() const noexcept
  {
    return user_id_;
  }

  void Token::set_user_id(std::string value)
  {
    user_id_ = std::move(value);
  }

  const std::string &Token::issuer() const noexcept
  {
    return issuer_;
  }

  void Token::set_issuer(std::string value)
  {
    issuer_ = std::move(value);
  }

  std::int64_t Token::issued_at() const noexcept
  {
    return issued_at_;
  }

  void Token::set_issued_at(std::int64_t value) noexcept
  {
    issued_at_ = value;
  }

  std::int64_t Token::expires_at() const noexcept
  {
    return expires_at_;
  }

  void Token::set_expires_at(std::int64_t value) noexcept
  {
    expires_at_ = value;
  }

  bool Token::revoked() const noexcept
  {
    return revoked_;
  }

  void Token::set_revoked(bool value) noexcept
  {
    revoked_ = value;
  }

  bool Token::valid() const noexcept
  {
    return !value_.empty() && !user_id_.empty();
  }

  bool Token::belongs_to(std::string_view value) const noexcept
  {
    return user_id_ == value;
  }

  bool Token::matches(std::string_view value) const noexcept
  {
    return value_ == value;
  }

  bool Token::expired(std::int64_t now) const noexcept
  {
    return expires_at_ > 0 && now >= expires_at_;
  }

  bool Token::usable(std::int64_t now) const noexcept
  {
    return valid() && !revoked_ && !expired(now);
  }
} // namespace rixlib::auth
