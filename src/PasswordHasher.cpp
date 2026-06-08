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

#include <functional>
#include <sstream>
#include <string>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] std::string make_basic_hash(std::string_view password)
    {
      const auto value = std::hash<std::string_view>{}(password);

      std::ostringstream stream;
      stream << "rix-auth-basic$" << value;

      return stream.str();
    }
  } // namespace

  PasswordHasher::PasswordHasher() = default;

  AuthResult<std::string> PasswordHasher::hash(std::string_view password) const
  {
    if (!accepts(password))
    {
      return AuthResult<std::string>::failure(
          make_auth_error(AuthErrorCode::InvalidPassword,
                          "Password does not satisfy the minimum length policy."));
    }

    return AuthResult<std::string>::success(make_basic_hash(password));
  }

  bool PasswordHasher::verify(std::string_view password,
                              std::string_view password_hash) const
  {
    if (!accepts(password) || password_hash.empty())
    {
      return false;
    }

    return make_basic_hash(password) == password_hash;
  }

  std::size_t PasswordHasher::min_password_length() const noexcept
  {
    return min_password_length_;
  }

  void PasswordHasher::set_min_password_length(std::size_t value) noexcept
  {
    min_password_length_ = value;
  }

  bool PasswordHasher::accepts(std::string_view password) const noexcept
  {
    return password.size() >= min_password_length_;
  }
} // namespace rixlib::auth
