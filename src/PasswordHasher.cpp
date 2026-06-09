/**
 *
 *  @file PasswordHasher.cpp
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

#include <rix/auth/PasswordHasher.hpp>
#include <vix/crypto/password.hpp>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] AuthError make_password_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::InvalidPassword,
          std::move(message));
    }

    [[nodiscard]] AuthError make_crypto_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::CryptoError,
          std::move(message));
    }
  } // namespace

  PasswordHasher::PasswordHasher()
      : PasswordHasher(AuthConfig::development())
  {
  }

  PasswordHasher::PasswordHasher(const AuthConfig &config)
      : min_password_length_(config.min_password_length()),
        max_password_length_(config.max_password_length()),
        iterations_(config.password_hash_iterations()),
        salt_size_(config.password_salt_size()),
        hash_size_(config.password_hash_size())
  {
  }

  AuthResult<std::string> PasswordHasher::hash(std::string_view password) const
  {
    if (password.empty())
    {
      return AuthResult<std::string>::failure(
          make_password_error("Password cannot be empty."));
    }

    if (password.size() < min_password_length_)
    {
      return AuthResult<std::string>::failure(
          make_password_error("Password does not satisfy the minimum length policy."));
    }

    if (password.size() > max_password_length_)
    {
      return AuthResult<std::string>::failure(
          make_password_error("Password exceeds the maximum length policy."));
    }

    vix::crypto::PasswordHashParams params;
    params.iterations = iterations_;
    params.salt_size = salt_size_;
    params.hash_size = hash_size_;

    auto hashed = vix::crypto::password_hash(password, params);

    if (!hashed.ok())
    {
      return AuthResult<std::string>::failure(
          make_crypto_error(std::string(hashed.error().message)));
    }

    return AuthResult<std::string>::success(hashed.value());
  }

  bool PasswordHasher::verify(
      std::string_view password,
      std::string_view password_hash) const
  {
    if (!accepts(password) || password_hash.empty())
    {
      return false;
    }

    auto verified = vix::crypto::password_verify(password, password_hash);

    if (!verified.ok())
    {
      return false;
    }

    return verified.value();
  }

  bool PasswordHasher::accepts(std::string_view password) const noexcept
  {
    return password.size() >= min_password_length_ &&
           password.size() <= max_password_length_;
  }

  std::size_t PasswordHasher::min_password_length() const noexcept
  {
    return min_password_length_;
  }

  void PasswordHasher::set_min_password_length(std::size_t value) noexcept
  {
    min_password_length_ = value;
  }

  std::size_t PasswordHasher::max_password_length() const noexcept
  {
    return max_password_length_;
  }

  void PasswordHasher::set_max_password_length(std::size_t value) noexcept
  {
    max_password_length_ = value;
  }

  std::uint32_t PasswordHasher::iterations() const noexcept
  {
    return iterations_;
  }

  void PasswordHasher::set_iterations(std::uint32_t value) noexcept
  {
    iterations_ = value;
  }

  std::size_t PasswordHasher::salt_size() const noexcept
  {
    return salt_size_;
  }

  void PasswordHasher::set_salt_size(std::size_t value) noexcept
  {
    salt_size_ = value;
  }

  std::size_t PasswordHasher::hash_size() const noexcept
  {
    return hash_size_;
  }

  void PasswordHasher::set_hash_size(std::size_t value) noexcept
  {
    hash_size_ = value;
  }
} // namespace rixlib::auth
