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

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] AuthError configuration_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::ConfigurationError,
          std::move(message));
    }

    [[nodiscard]] AuthError invalid_store_error(std::string message)
    {
      return make_auth_error(
          AuthErrorCode::InvalidState,
          std::move(message));
    }
  } // namespace

  AuthError AuthErrorModule::none() const
  {
    return make_auth_ok();
  }

  AuthError AuthErrorModule::make(
      AuthErrorCode code,
      std::string message) const
  {
    return make_auth_error(code, std::move(message));
  }

  std::string_view AuthErrorModule::to_string(
      AuthErrorCode code) const noexcept
  {
    return rixlib::auth::to_string(code);
  }

  std::string_view AuthErrorModule::to_string(
      const AuthError &error) const noexcept
  {
    return rixlib::auth::to_string(error.code());
  }

  bool AuthErrorModule::ok(const AuthError &error) const noexcept
  {
    return error.ok();
  }

  bool AuthErrorModule::failed(const AuthError &error) const noexcept
  {
    return error.has_error();
  }

  bool AuthErrorModule::is(
      const AuthError &error,
      AuthErrorCode code) const noexcept
  {
    return error.is(code);
  }

  AuthConfig AuthConfigModule::development() const
  {
    return AuthConfig::development();
  }

  AuthConfig AuthConfigModule::production() const
  {
    return AuthConfig::production();
  }

  AuthConfig AuthConfigModule::development_with_min_password_length(
      std::size_t min_length) const
  {
    auto config = AuthConfig::development();
    config.set_min_password_length(min_length);
    return config;
  }

  AuthConfig AuthConfigModule::production_with_min_password_length(
      std::size_t min_length) const
  {
    auto config = AuthConfig::production();
    config.set_min_password_length(min_length);
    return config;
  }

  bool AuthConfigModule::valid(const AuthConfig &config) const noexcept
  {
    return validate(config).ok();
  }

  AuthStatus AuthConfigModule::validate(const AuthConfig &config) const
  {
    if (config.min_password_length() == 0)
    {
      return AuthStatus::failure(
          configuration_error("Minimum password length must be greater than zero."));
    }

    if (config.max_password_length() == 0)
    {
      return AuthStatus::failure(
          configuration_error("Maximum password length must be greater than zero."));
    }

    if (config.min_password_length() > config.max_password_length())
    {
      return AuthStatus::failure(
          configuration_error(
              "Minimum password length cannot be greater than maximum password length."));
    }

    if (config.session_ttl_seconds() <= 0)
    {
      return AuthStatus::failure(
          configuration_error("Session lifetime must be greater than zero."));
    }

    if (config.token_ttl_seconds() <= 0)
    {
      return AuthStatus::failure(
          configuration_error("Token lifetime must be greater than zero."));
    }

    if (config.password_hash_iterations() == 0)
    {
      return AuthStatus::failure(
          configuration_error("Password hash iterations must be greater than zero."));
    }

    if (config.password_salt_size() == 0)
    {
      return AuthStatus::failure(
          configuration_error("Password salt size must be greater than zero."));
    }

    if (config.password_hash_size() == 0)
    {
      return AuthStatus::failure(
          configuration_error("Password hash size must be greater than zero."));
    }

    if (config.issuer().empty())
    {
      return AuthStatus::failure(
          configuration_error("Token issuer cannot be empty."));
    }

    return AuthStatus::success();
  }

  AuthResult<std::string> AuthPasswordModule::hash(
      std::string_view password) const
  {
    PasswordHasher hasher;
    return hasher.hash(password);
  }

  AuthResult<std::string> AuthPasswordModule::hash(
      std::string_view password,
      const AuthConfig &config) const
  {
    PasswordHasher hasher(config);
    return hasher.hash(password);
  }

  bool AuthPasswordModule::verify(
      std::string_view password,
      std::string_view password_hash) const
  {
    PasswordHasher hasher;
    return hasher.verify(password, password_hash);
  }

  bool AuthPasswordModule::verify(
      std::string_view password,
      std::string_view password_hash,
      const AuthConfig &config) const
  {
    PasswordHasher hasher(config);
    return hasher.verify(password, password_hash);
  }

  bool AuthPasswordModule::accepts(std::string_view password) const
  {
    PasswordHasher hasher;
    return hasher.accepts(password);
  }

  bool AuthPasswordModule::accepts(
      std::string_view password,
      const AuthConfig &config) const
  {
    PasswordHasher hasher(config);
    return hasher.accepts(password);
  }

  PasswordHasher AuthPasswordModule::hasher() const
  {
    return PasswordHasher{};
  }

  PasswordHasher AuthPasswordModule::hasher(const AuthConfig &config) const
  {
    return PasswordHasher{config};
  }

  std::unique_ptr<UserStore> AuthStoreModule::memory_users() const
  {
    return std::make_unique<MemoryUserStore>();
  }

  std::unique_ptr<SessionStore> AuthStoreModule::memory_sessions() const
  {
    return std::make_unique<MemorySessionStore>();
  }

  std::unique_ptr<UserStore> AuthStoreModule::database_users(
      vix::db::Database &database) const
  {
    return std::make_unique<DbUserStore>(database);
  }

  std::unique_ptr<SessionStore> AuthStoreModule::database_sessions(
      vix::db::Database &database) const
  {
    return std::make_unique<DbSessionStore>(database);
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

  AuthResult<ManagedAuth> AuthModule::managed(
      std::unique_ptr<UserStore> users,
      std::unique_ptr<SessionStore> sessions) const
  {
    return managed(
        std::move(users),
        std::move(sessions),
        AuthConfig::development());
  }

  AuthResult<ManagedAuth> AuthModule::managed(
      std::unique_ptr<UserStore> users,
      std::unique_ptr<SessionStore> sessions,
      AuthConfig config) const
  {
    if (!users)
    {
      return AuthResult<ManagedAuth>::failure(
          invalid_store_error("User store cannot be null."));
    }

    if (!sessions)
    {
      return AuthResult<ManagedAuth>::failure(
          invalid_store_error("Session store cannot be null."));
    }

    const auto validation = this->config.validate(config);

    if (validation.failed())
    {
      return AuthResult<ManagedAuth>::failure(validation.error());
    }

    return AuthResult<ManagedAuth>::success(
        ManagedAuth{
            std::move(users),
            std::move(sessions),
            std::move(config)});
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
