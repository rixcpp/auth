/**
 *
 *  @file DbUserStore.cpp
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

#include <rix/auth/stores/DbUserStore.hpp>

#include <vix/db/Database.hpp>
#include <vix/db/core/Result.hpp>

#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace rixlib::auth
{
  DbUserStore::DbUserStore(vix::db::Database &database, bool create_schema)
      : database_(&database)
  {
    if (create_schema)
    {
      (void)ensure_schema();
    }
  }

  AuthStatus DbUserStore::create(const User &user)
  {
    if (!user.valid())
    {
      return AuthStatus::failure(invalid_user_error());
    }

    try
    {
      auto exists_id = exists_by_id(user.id());
      if (exists_id.failed())
      {
        return AuthStatus::failure(exists_id.error());
      }

      if (exists_id.value())
      {
        return AuthStatus::failure(user_already_exists_error());
      }

      auto exists_email = exists_by_email(user.email());
      if (exists_email.failed())
      {
        return AuthStatus::failure(exists_email.error());
      }

      if (exists_email.value())
      {
        return AuthStatus::failure(user_already_exists_error());
      }

      database_->exec(
          "INSERT INTO rix_auth_users "
          "(id, email, password_hash, email_verified, active, created_at, updated_at) "
          "VALUES (?, ?, ?, ?, ?, ?, ?)",
          user.id(),
          user.email(),
          user.password_hash(),
          user.email_verified(),
          user.active(),
          user.created_at(),
          user.updated_at());

      return AuthStatus::success();
    }
    catch (const std::exception &e)
    {
      return AuthStatus::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthStatus::failure(store_error("Unknown database error."));
    }
  }

  AuthStatus DbUserStore::update(const User &user)
  {
    if (!user.valid())
    {
      return AuthStatus::failure(invalid_user_error());
    }

    try
    {
      auto existing = find_by_id(user.id());
      if (existing.failed())
      {
        return AuthStatus::failure(existing.error());
      }

      if (!existing.value().has_value())
      {
        return AuthStatus::failure(user_not_found_error());
      }

      auto owner = find_by_email(user.email());
      if (owner.failed())
      {
        return AuthStatus::failure(owner.error());
      }

      if (owner.value().has_value() && !owner.value()->has_id(user.id()))
      {
        return AuthStatus::failure(user_already_exists_error());
      }

      database_->exec(
          "UPDATE rix_auth_users "
          "SET email = ?, "
          "password_hash = ?, "
          "email_verified = ?, "
          "active = ?, "
          "created_at = ?, "
          "updated_at = ? "
          "WHERE id = ?",
          user.email(),
          user.password_hash(),
          user.email_verified(),
          user.active(),
          user.created_at(),
          user.updated_at(),
          user.id());

      return AuthStatus::success();
    }
    catch (const std::exception &e)
    {
      return AuthStatus::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthStatus::failure(store_error("Unknown database error."));
    }
  }

  AuthStatus DbUserStore::remove_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_id_error());
    }

    try
    {
      auto existing = exists_by_id(id);
      if (existing.failed())
      {
        return AuthStatus::failure(existing.error());
      }

      if (!existing.value())
      {
        return AuthStatus::failure(user_not_found_error());
      }

      database_->exec(
          "DELETE FROM rix_auth_users WHERE id = ?",
          std::string(id));

      return AuthStatus::success();
    }
    catch (const std::exception &e)
    {
      return AuthStatus::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthStatus::failure(store_error("Unknown database error."));
    }
  }

  AuthResult<std::optional<User>>
  DbUserStore::find_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<std::optional<User>>::failure(empty_id_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id, email, password_hash, email_verified, active, created_at, updated_at "
          "FROM rix_auth_users "
          "WHERE id = ? "
          "LIMIT 1",
          std::string(id));

      if (!result->next())
      {
        return AuthResult<std::optional<User>>::success(std::nullopt);
      }

      return AuthResult<std::optional<User>>::success(
          row_to_user(result->row()));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::optional<User>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::optional<User>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthResult<std::optional<User>>
  DbUserStore::find_by_email(std::string_view email) const
  {
    if (email.empty())
    {
      return AuthResult<std::optional<User>>::failure(empty_email_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id, email, password_hash, email_verified, active, created_at, updated_at "
          "FROM rix_auth_users "
          "WHERE email = ? "
          "LIMIT 1",
          std::string(email));

      if (!result->next())
      {
        return AuthResult<std::optional<User>>::success(std::nullopt);
      }

      return AuthResult<std::optional<User>>::success(
          row_to_user(result->row()));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::optional<User>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::optional<User>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthResult<bool>
  DbUserStore::exists_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<bool>::failure(empty_id_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id FROM rix_auth_users WHERE id = ? LIMIT 1",
          std::string(id));

      return AuthResult<bool>::success(result->next());
    }
    catch (const std::exception &e)
    {
      return AuthResult<bool>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<bool>::failure(store_error("Unknown database error."));
    }
  }

  AuthResult<bool>
  DbUserStore::exists_by_email(std::string_view email) const
  {
    if (email.empty())
    {
      return AuthResult<bool>::failure(empty_email_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id FROM rix_auth_users WHERE email = ? LIMIT 1",
          std::string(email));

      return AuthResult<bool>::success(result->next());
    }
    catch (const std::exception &e)
    {
      return AuthResult<bool>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<bool>::failure(store_error("Unknown database error."));
    }
  }

  AuthResult<std::vector<User>> DbUserStore::all() const
  {
    try
    {
      auto result = database_->query(
          "SELECT id, email, password_hash, email_verified, active, created_at, updated_at "
          "FROM rix_auth_users "
          "ORDER BY created_at ASC");

      std::vector<User> users;

      while (result->next())
      {
        users.push_back(row_to_user(result->row()));
      }

      return AuthResult<std::vector<User>>::success(std::move(users));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::vector<User>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::vector<User>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthStatus DbUserStore::ensure_schema()
  {
    try
    {
      database_->exec(
          "CREATE TABLE IF NOT EXISTS rix_auth_users ("
          "id VARCHAR(128) NOT NULL PRIMARY KEY,"
          "email VARCHAR(320) NOT NULL UNIQUE,"
          "password_hash TEXT NOT NULL,"
          "email_verified INTEGER NOT NULL DEFAULT 0,"
          "active INTEGER NOT NULL DEFAULT 1,"
          "created_at BIGINT NOT NULL,"
          "updated_at BIGINT NOT NULL"
          ")");

      return AuthStatus::success();
    }
    catch (const std::exception &e)
    {
      return AuthStatus::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthStatus::failure(store_error("Unknown database error."));
    }
  }

  User DbUserStore::row_to_user(const vix::db::ResultRow &row)
  {
    User user{
        row.getString(0),
        row.getString(1),
        row.getString(2),
        row.getInt64(5)};

    user.set_email_verified(row.getInt64(3) != 0);
    user.set_active(row.getInt64(4) != 0);
    user.set_updated_at(row.getInt64(6));

    return user;
  }

  AuthError DbUserStore::store_error(std::string message)
  {
    return make_auth_error(
        AuthErrorCode::StoreError,
        std::move(message));
  }

  AuthError DbUserStore::invalid_user_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidInput,
        "User is invalid.");
  }

  AuthError DbUserStore::empty_id_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidInput,
        "User id cannot be empty.");
  }

  AuthError DbUserStore::empty_email_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidEmail,
        "User email cannot be empty.");
  }

  AuthError DbUserStore::user_not_found_error()
  {
    return make_auth_error(
        AuthErrorCode::UserNotFound,
        "User not found.");
  }

  AuthError DbUserStore::user_already_exists_error()
  {
    return make_auth_error(
        AuthErrorCode::UserAlreadyExists,
        "User already exists.");
  }
} // namespace rixlib::auth
