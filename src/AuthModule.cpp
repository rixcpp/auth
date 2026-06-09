/**
 *
 *  @file AuthModule.cpp
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

#include <rix/auth/AuthModule.hpp>

#include <memory>
#include <utility>

namespace rixlib::auth
{
  AuthConfig AuthConfigModule::development() const
  {
    return AuthConfig::development();
  }

  AuthConfig AuthConfigModule::production() const
  {
    return AuthConfig::production();
  }

  AuthResult<std::string> AuthPasswordModule::hash(
      std::string_view password) const
  {
    PasswordHasher hasher;
    return hasher.hash(password);
  }

  bool AuthPasswordModule::verify(
      std::string_view password,
      std::string_view password_hash) const
  {
    PasswordHasher hasher;
    return hasher.verify(password, password_hash);
  }

  PasswordHasher AuthPasswordModule::hasher() const
  {
    return PasswordHasher{};
  }

  Auth AuthModule::create(
      UserStore &users,
      SessionStore &sessions) const
  {
    return Auth{
        users,
        sessions,
        AuthConfig::development()};
  }

  Auth AuthModule::create(
      UserStore &users,
      SessionStore &sessions,
      AuthConfig config) const
  {
    return Auth{
        users,
        sessions,
        std::move(config)};
  }

  ManagedAuth AuthModule::memory() const
  {
    return memory(AuthConfig::development());
  }

  ManagedAuth AuthModule::memory(AuthConfig config) const
  {
    auto users = std::make_unique<MemoryUserStore>();
    auto sessions = std::make_unique<MemorySessionStore>();

    return ManagedAuth{
        std::move(users),
        std::move(sessions),
        std::move(config)};
  }

  ManagedAuth AuthModule::database(vix::db::Database &database) const
  {
    return this->database(
        database,
        AuthConfig::production());
  }

  ManagedAuth AuthModule::database(
      vix::db::Database &database,
      AuthConfig config) const
  {
    auto users = std::make_unique<DbUserStore>(database);
    auto sessions = std::make_unique<DbSessionStore>(database);

    return ManagedAuth{
        std::move(users),
        std::move(sessions),
        std::move(config)};
  }

  std::string AuthModule::version() const
  {
    return rixlib::auth::version();
  }

  int AuthModule::version_major() const noexcept
  {
    return rixlib::auth::version_major();
  }

  int AuthModule::version_minor() const noexcept
  {
    return rixlib::auth::version_minor();
  }

  int AuthModule::version_patch() const noexcept
  {
    return rixlib::auth::version_patch();
  }

  int AuthModule::version_number() const noexcept
  {
    return rixlib::auth::version_number();
  }
} // namespace rixlib::auth
