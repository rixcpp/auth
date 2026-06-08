/**
 *
 *  @file DbSessionStore.cpp
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

#include <rix/auth/stores/DbSessionStore.hpp>

#include <vix/db/Database.hpp>
#include <vix/db/core/Result.hpp>

#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace rixlib::auth
{
  DbSessionStore::DbSessionStore(vix::db::Database &database, bool create_schema)
      : database_(&database)
  {
    if (create_schema)
    {
      (void)ensure_schema();
    }
  }

  AuthStatus DbSessionStore::create(const Session &session)
  {
    if (!session.valid())
    {
      return AuthStatus::failure(invalid_session_error());
    }

    try
    {
      auto exists = exists_by_id(session.id());

      if (exists.failed())
      {
        return AuthStatus::failure(exists.error());
      }

      if (exists.value())
      {
        return AuthStatus::failure(session_already_exists_error());
      }

      database_->exec(
          "INSERT INTO rix_auth_sessions "
          "(id, user_id, created_at, expires_at, last_seen_at, revoked) "
          "VALUES (?, ?, ?, ?, ?, ?)",
          session.id(),
          session.user_id(),
          session.created_at(),
          session.expires_at(),
          session.last_seen_at(),
          session.revoked());

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

  AuthStatus DbSessionStore::update(const Session &session)
  {
    if (!session.valid())
    {
      return AuthStatus::failure(invalid_session_error());
    }

    try
    {
      auto exists = exists_by_id(session.id());

      if (exists.failed())
      {
        return AuthStatus::failure(exists.error());
      }

      if (!exists.value())
      {
        return AuthStatus::failure(session_not_found_error());
      }

      database_->exec(
          "UPDATE rix_auth_sessions "
          "SET user_id = ?, "
          "created_at = ?, "
          "expires_at = ?, "
          "last_seen_at = ?, "
          "revoked = ? "
          "WHERE id = ?",
          session.user_id(),
          session.created_at(),
          session.expires_at(),
          session.last_seen_at(),
          session.revoked(),
          session.id());

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

  AuthStatus DbSessionStore::remove_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_session_id_error());
    }

    try
    {
      auto exists = exists_by_id(id);

      if (exists.failed())
      {
        return AuthStatus::failure(exists.error());
      }

      if (!exists.value())
      {
        return AuthStatus::failure(session_not_found_error());
      }

      database_->exec(
          "DELETE FROM rix_auth_sessions WHERE id = ?",
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

  AuthStatus DbSessionStore::revoke_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_session_id_error());
    }

    try
    {
      auto exists = exists_by_id(id);

      if (exists.failed())
      {
        return AuthStatus::failure(exists.error());
      }

      if (!exists.value())
      {
        return AuthStatus::failure(session_not_found_error());
      }

      database_->exec(
          "UPDATE rix_auth_sessions "
          "SET revoked = 1 "
          "WHERE id = ?",
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

  AuthStatus DbSessionStore::revoke_by_user_id(std::string_view user_id)
  {
    if (user_id.empty())
    {
      return AuthStatus::failure(empty_user_id_error());
    }

    try
    {
      database_->exec(
          "UPDATE rix_auth_sessions "
          "SET revoked = 1 "
          "WHERE user_id = ?",
          std::string(user_id));

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

  AuthResult<std::optional<Session>>
  DbSessionStore::find_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<std::optional<Session>>::failure(
          empty_session_id_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id, user_id, created_at, expires_at, last_seen_at, revoked "
          "FROM rix_auth_sessions "
          "WHERE id = ? "
          "LIMIT 1",
          std::string(id));

      if (!result->next())
      {
        return AuthResult<std::optional<Session>>::success(std::nullopt);
      }

      return AuthResult<std::optional<Session>>::success(
          row_to_session(result->row()));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::optional<Session>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::optional<Session>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthResult<std::vector<Session>>
  DbSessionStore::find_by_user_id(std::string_view user_id) const
  {
    if (user_id.empty())
    {
      return AuthResult<std::vector<Session>>::failure(
          empty_user_id_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id, user_id, created_at, expires_at, last_seen_at, revoked "
          "FROM rix_auth_sessions "
          "WHERE user_id = ? "
          "ORDER BY created_at DESC",
          std::string(user_id));

      std::vector<Session> sessions;

      while (result->next())
      {
        sessions.push_back(row_to_session(result->row()));
      }

      return AuthResult<std::vector<Session>>::success(std::move(sessions));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::vector<Session>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::vector<Session>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthResult<bool>
  DbSessionStore::exists_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<bool>::failure(empty_session_id_error());
    }

    try
    {
      auto result = database_->query(
          "SELECT id FROM rix_auth_sessions WHERE id = ? LIMIT 1",
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

  AuthResult<std::vector<Session>> DbSessionStore::all() const
  {
    try
    {
      auto result = database_->query(
          "SELECT id, user_id, created_at, expires_at, last_seen_at, revoked "
          "FROM rix_auth_sessions "
          "ORDER BY created_at DESC");

      std::vector<Session> sessions;

      while (result->next())
      {
        sessions.push_back(row_to_session(result->row()));
      }

      return AuthResult<std::vector<Session>>::success(std::move(sessions));
    }
    catch (const std::exception &e)
    {
      return AuthResult<std::vector<Session>>::failure(store_error(e.what()));
    }
    catch (...)
    {
      return AuthResult<std::vector<Session>>::failure(
          store_error("Unknown database error."));
    }
  }

  AuthStatus DbSessionStore::ensure_schema()
  {
    try
    {
      database_->exec(
          "CREATE TABLE IF NOT EXISTS rix_auth_sessions ("
          "id VARCHAR(128) NOT NULL PRIMARY KEY,"
          "user_id VARCHAR(128) NOT NULL,"
          "created_at BIGINT NOT NULL,"
          "expires_at BIGINT NOT NULL,"
          "last_seen_at BIGINT NOT NULL,"
          "revoked INTEGER NOT NULL DEFAULT 0"
          ")");

      database_->exec(
          "CREATE INDEX IF NOT EXISTS idx_rix_auth_sessions_user_id "
          "ON rix_auth_sessions (user_id)");

      database_->exec(
          "CREATE INDEX IF NOT EXISTS idx_rix_auth_sessions_expires_at "
          "ON rix_auth_sessions (expires_at)");

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

  Session DbSessionStore::row_to_session(const vix::db::ResultRow &row)
  {
    Session session{
        row.getString(0),
        row.getString(1),
        row.getInt64(2),
        row.getInt64(3)};

    session.set_last_seen_at(row.getInt64(4));
    session.set_revoked(row.getInt64(5) != 0);

    return session;
  }

  AuthError DbSessionStore::store_error(std::string message)
  {
    return make_auth_error(
        AuthErrorCode::StoreError,
        std::move(message));
  }

  AuthError DbSessionStore::invalid_session_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidSession,
        "Session is invalid.");
  }

  AuthError DbSessionStore::empty_session_id_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidSession,
        "Session id cannot be empty.");
  }

  AuthError DbSessionStore::empty_user_id_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidInput,
        "User id cannot be empty.");
  }

  AuthError DbSessionStore::session_not_found_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidSession,
        "Session not found.");
  }

  AuthError DbSessionStore::session_already_exists_error()
  {
    return make_auth_error(
        AuthErrorCode::InvalidSession,
        "Session already exists.");
  }
} // namespace rixlib::auth
