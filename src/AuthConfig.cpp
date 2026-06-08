/**
 *
 *  @file AuthConfig.cpp
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

#include <rix/auth/AuthConfig.hpp>

#include <utility>

namespace rixlib::auth
{
  AuthConfig::AuthConfig() = default;

  AuthConfig AuthConfig::development()
  {
    AuthConfig config;

    config.set_min_password_length(8);
    config.set_max_password_length(1024);

    config.set_session_ttl_seconds(60 * 60 * 24 * 7);
    config.set_token_ttl_seconds(60 * 15);

    config.set_password_hash_iterations(310000);
    config.set_password_salt_size(16);
    config.set_password_hash_size(32);

    config.set_issuer("rix/auth");
    config.set_require_email_verification(false);
    config.set_rotate_sessions(true);
    config.set_reject_inactive_users(true);

    return config;
  }

  AuthConfig AuthConfig::production()
  {
    AuthConfig config;

    config.set_min_password_length(12);
    config.set_max_password_length(1024);

    config.set_session_ttl_seconds(60 * 60 * 24 * 7);
    config.set_token_ttl_seconds(60 * 10);

    config.set_password_hash_iterations(310000);
    config.set_password_salt_size(16);
    config.set_password_hash_size(32);

    config.set_issuer("rix/auth");
    config.set_require_email_verification(true);
    config.set_rotate_sessions(true);
    config.set_reject_inactive_users(true);

    return config;
  }

  std::size_t AuthConfig::min_password_length() const noexcept
  {
    return min_password_length_;
  }

  void AuthConfig::set_min_password_length(std::size_t value) noexcept
  {
    min_password_length_ = value;
  }

  std::size_t AuthConfig::max_password_length() const noexcept
  {
    return max_password_length_;
  }

  void AuthConfig::set_max_password_length(std::size_t value) noexcept
  {
    max_password_length_ = value;
  }

  std::int64_t AuthConfig::session_ttl_seconds() const noexcept
  {
    return session_ttl_seconds_;
  }

  void AuthConfig::set_session_ttl_seconds(std::int64_t value) noexcept
  {
    session_ttl_seconds_ = value;
  }

  std::int64_t AuthConfig::token_ttl_seconds() const noexcept
  {
    return token_ttl_seconds_;
  }

  void AuthConfig::set_token_ttl_seconds(std::int64_t value) noexcept
  {
    token_ttl_seconds_ = value;
  }

  std::uint32_t AuthConfig::password_hash_iterations() const noexcept
  {
    return password_hash_iterations_;
  }

  void AuthConfig::set_password_hash_iterations(std::uint32_t value) noexcept
  {
    password_hash_iterations_ = value;
  }

  std::size_t AuthConfig::password_salt_size() const noexcept
  {
    return password_salt_size_;
  }

  void AuthConfig::set_password_salt_size(std::size_t value) noexcept
  {
    password_salt_size_ = value;
  }

  std::size_t AuthConfig::password_hash_size() const noexcept
  {
    return password_hash_size_;
  }

  void AuthConfig::set_password_hash_size(std::size_t value) noexcept
  {
    password_hash_size_ = value;
  }

  const std::string &AuthConfig::issuer() const noexcept
  {
    return issuer_;
  }

  void AuthConfig::set_issuer(std::string value)
  {
    issuer_ = std::move(value);
  }

  bool AuthConfig::require_email_verification() const noexcept
  {
    return require_email_verification_;
  }

  void AuthConfig::set_require_email_verification(bool value) noexcept
  {
    require_email_verification_ = value;
  }

  bool AuthConfig::rotate_sessions() const noexcept
  {
    return rotate_sessions_;
  }

  void AuthConfig::set_rotate_sessions(bool value) noexcept
  {
    rotate_sessions_ = value;
  }

  bool AuthConfig::reject_inactive_users() const noexcept
  {
    return reject_inactive_users_;
  }

  void AuthConfig::set_reject_inactive_users(bool value) noexcept
  {
    reject_inactive_users_ = value;
  }
} // namespace rixlib::auth
