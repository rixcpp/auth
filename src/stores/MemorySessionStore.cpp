/**
 *
 *  @file MemorySessionStore.cpp
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

#include <rix/auth/stores/MemorySessionStore.hpp>

#include <optional>
#include <utility>

namespace rixlib::auth
{
  namespace
  {
    [[nodiscard]] AuthError invalid_session_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidSession,
          "Session is invalid.");
    }

    [[nodiscard]] AuthError empty_session_id_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidSession,
          "Session id cannot be empty.");
    }

    [[nodiscard]] AuthError empty_user_id_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidInput,
          "User id cannot be empty.");
    }

    [[nodiscard]] AuthError session_not_found_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidSession,
          "Session not found.");
    }

    [[nodiscard]] AuthError session_already_exists_error()
    {
      return make_auth_error(
          AuthErrorCode::InvalidSession,
          "Session already exists.");
    }
  } // namespace

  AuthStatus MemorySessionStore::create(const Session &session)
  {
    if (!session.valid())
    {
      return AuthStatus::failure(invalid_session_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(session.id());

    if (sessions_by_id_.find(id_key) != sessions_by_id_.end())
    {
      return AuthStatus::failure(session_already_exists_error());
    }

    sessions_by_id_.emplace(id_key, session);
    index_session_locked(session);

    return AuthStatus::success();
  }

  AuthStatus MemorySessionStore::update(const Session &session)
  {
    if (!session.valid())
    {
      return AuthStatus::failure(invalid_session_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(session.id());
    const auto existing = sessions_by_id_.find(id_key);

    if (existing == sessions_by_id_.end())
    {
      return AuthStatus::failure(session_not_found_error());
    }

    unindex_session_locked(existing->second);

    existing->second = session;

    index_session_locked(existing->second);

    return AuthStatus::success();
  }

  AuthStatus MemorySessionStore::remove_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_session_id_error());
    }

    std::lock_guard lock(mutex_);

    const std::string id_key = key(id);
    const auto existing = sessions_by_id_.find(id_key);

    if (existing == sessions_by_id_.end())
    {
      return AuthStatus::failure(session_not_found_error());
    }

    unindex_session_locked(existing->second);
    sessions_by_id_.erase(existing);

    return AuthStatus::success();
  }

  AuthStatus MemorySessionStore::revoke_by_id(std::string_view id)
  {
    if (id.empty())
    {
      return AuthStatus::failure(empty_session_id_error());
    }

    std::lock_guard lock(mutex_);

    const auto existing = sessions_by_id_.find(key(id));

    if (existing == sessions_by_id_.end())
    {
      return AuthStatus::failure(session_not_found_error());
    }

    existing->second.revoke();

    return AuthStatus::success();
  }

  AuthStatus MemorySessionStore::revoke_by_user_id(std::string_view user_id)
  {
    if (user_id.empty())
    {
      return AuthStatus::failure(empty_user_id_error());
    }

    std::lock_guard lock(mutex_);

    const auto index_it = ids_by_user_id_.find(key(user_id));

    if (index_it == ids_by_user_id_.end())
    {
      return AuthStatus::success();
    }

    for (const auto &session_id : index_it->second)
    {
      const auto session_it = sessions_by_id_.find(session_id);

      if (session_it != sessions_by_id_.end())
      {
        session_it->second.revoke();
      }
    }

    return AuthStatus::success();
  }

  AuthResult<std::optional<Session>>
  MemorySessionStore::find_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<std::optional<Session>>::failure(
          empty_session_id_error());
    }

    std::lock_guard lock(mutex_);

    const auto it = sessions_by_id_.find(key(id));

    if (it == sessions_by_id_.end())
    {
      return AuthResult<std::optional<Session>>::success(std::nullopt);
    }

    return AuthResult<std::optional<Session>>::success(it->second);
  }

  AuthResult<std::vector<Session>>
  MemorySessionStore::find_by_user_id(std::string_view user_id) const
  {
    if (user_id.empty())
    {
      return AuthResult<std::vector<Session>>::failure(
          empty_user_id_error());
    }

    std::lock_guard lock(mutex_);

    std::vector<Session> sessions;

    const auto index_it = ids_by_user_id_.find(key(user_id));

    if (index_it == ids_by_user_id_.end())
    {
      return AuthResult<std::vector<Session>>::success(std::move(sessions));
    }

    sessions.reserve(index_it->second.size());

    for (const auto &session_id : index_it->second)
    {
      const auto session_it = sessions_by_id_.find(session_id);

      if (session_it != sessions_by_id_.end())
      {
        sessions.push_back(session_it->second);
      }
    }

    return AuthResult<std::vector<Session>>::success(std::move(sessions));
  }

  AuthResult<bool>
  MemorySessionStore::exists_by_id(std::string_view id) const
  {
    if (id.empty())
    {
      return AuthResult<bool>::failure(empty_session_id_error());
    }

    std::lock_guard lock(mutex_);

    return AuthResult<bool>::success(
        sessions_by_id_.find(key(id)) != sessions_by_id_.end());
  }

  AuthResult<std::vector<Session>> MemorySessionStore::all() const
  {
    std::lock_guard lock(mutex_);

    std::vector<Session> sessions;
    sessions.reserve(sessions_by_id_.size());

    for (const auto &[id, session] : sessions_by_id_)
    {
      (void)id;
      sessions.push_back(session);
    }

    return AuthResult<std::vector<Session>>::success(std::move(sessions));
  }

  void MemorySessionStore::clear()
  {
    std::lock_guard lock(mutex_);

    sessions_by_id_.clear();
    ids_by_user_id_.clear();
  }

  std::size_t MemorySessionStore::size() const
  {
    std::lock_guard lock(mutex_);

    return sessions_by_id_.size();
  }

  bool MemorySessionStore::empty() const
  {
    return size() == 0;
  }

  std::string MemorySessionStore::key(std::string_view value)
  {
    return std::string(value);
  }

  void MemorySessionStore::index_session_locked(const Session &session)
  {
    ids_by_user_id_[key(session.user_id())].insert(key(session.id()));
  }

  void MemorySessionStore::unindex_session_locked(const Session &session)
  {
    const std::string user_key = key(session.user_id());
    const std::string id_key = key(session.id());

    const auto index_it = ids_by_user_id_.find(user_key);

    if (index_it == ids_by_user_id_.end())
    {
      return;
    }

    index_it->second.erase(id_key);

    if (index_it->second.empty())
    {
      ids_by_user_id_.erase(index_it);
    }
  }
} // namespace rixlib::auth
