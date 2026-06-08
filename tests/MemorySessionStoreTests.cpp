/**
 *
 *  @file MemorySessionStoreTests.cpp
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

#include <rix/auth/AuthError.hpp>
#include <rix/auth/stores/MemorySessionStore.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::AuthErrorCode;
  using rixlib::auth::MemorySessionStore;
  using rixlib::auth::Session;

  [[nodiscard]] Session make_session(
      std::string id = "session_1",
      std::string user_id = "user_1")
  {
    return Session{
        std::move(id),
        std::move(user_id),
        1000,
        2000};
  }

  TEST(MemorySessionStoreTests, StartsEmpty)
  {
    const MemorySessionStore store;

    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0);
  }

  TEST(MemorySessionStoreTests, CreateStoresSession)
  {
    MemorySessionStore store;

    const auto status = store.create(make_session());

    EXPECT_TRUE(status.ok());
    EXPECT_FALSE(store.empty());
    EXPECT_EQ(store.size(), 1);
  }

  TEST(MemorySessionStoreTests, CreateRejectsInvalidSession)
  {
    MemorySessionStore store;

    const Session session;

    const auto status = store.create(session);

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidSession);
    EXPECT_TRUE(store.empty());
  }

  TEST(MemorySessionStoreTests, CreateRejectsDuplicateSessionId)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    const auto status = store.create(make_session("session_1", "user_2"));

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(MemorySessionStoreTests, FindByIdReturnsStoredSession)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    const auto found = store.find_by_id("session_1");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->id(), "session_1");
    EXPECT_EQ(found.value()->user_id(), "user_1");
  }

  TEST(MemorySessionStoreTests, FindByIdReturnsEmptyOptionalWhenMissing)
  {
    MemorySessionStore store;

    const auto found = store.find_by_id("missing");

    ASSERT_TRUE(found.ok());
    EXPECT_FALSE(found.value().has_value());
  }

  TEST(MemorySessionStoreTests, FindByIdRejectsEmptyId)
  {
    MemorySessionStore store;

    const auto found = store.find_by_id("");

    ASSERT_TRUE(found.failed());
    EXPECT_EQ(found.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(MemorySessionStoreTests, FindByUserIdReturnsMatchingSessions)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_2", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_3", "user_2")).ok());

    const auto sessions = store.find_by_user_id("user_1");

    ASSERT_TRUE(sessions.ok());
    EXPECT_EQ(sessions.value().size(), 2);

    for (const auto &session : sessions.value())
    {
      EXPECT_TRUE(session.belongs_to("user_1"));
    }
  }

  TEST(MemorySessionStoreTests, FindByUserIdReturnsEmptyVectorWhenMissing)
  {
    MemorySessionStore store;

    const auto sessions = store.find_by_user_id("missing");

    ASSERT_TRUE(sessions.ok());
    EXPECT_TRUE(sessions.value().empty());
  }

  TEST(MemorySessionStoreTests, FindByUserIdRejectsEmptyUserId)
  {
    MemorySessionStore store;

    const auto sessions = store.find_by_user_id("");

    ASSERT_TRUE(sessions.failed());
    EXPECT_EQ(sessions.error().code(), AuthErrorCode::InvalidInput);
  }

  TEST(MemorySessionStoreTests, ExistsByIdReturnsExpectedState)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    const auto existing = store.exists_by_id("session_1");
    const auto missing = store.exists_by_id("missing");

    ASSERT_TRUE(existing.ok());
    ASSERT_TRUE(missing.ok());

    EXPECT_TRUE(existing.value());
    EXPECT_FALSE(missing.value());
  }

  TEST(MemorySessionStoreTests, UpdateChangesStoredSession)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    Session session = make_session("session_1", "user_2");
    session.set_last_seen_at(1500);
    session.set_expires_at(5000);
    session.set_revoked(true);

    const auto status = store.update(session);

    ASSERT_TRUE(status.ok());

    const auto found = store.find_by_id("session_1");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());

    EXPECT_EQ(found.value()->user_id(), "user_2");
    EXPECT_EQ(found.value()->last_seen_at(), 1500);
    EXPECT_EQ(found.value()->expires_at(), 5000);
    EXPECT_TRUE(found.value()->revoked());

    const auto old_user_sessions = store.find_by_user_id("user_1");
    const auto new_user_sessions = store.find_by_user_id("user_2");

    ASSERT_TRUE(old_user_sessions.ok());
    ASSERT_TRUE(new_user_sessions.ok());

    EXPECT_TRUE(old_user_sessions.value().empty());
    EXPECT_EQ(new_user_sessions.value().size(), 1);
  }

  TEST(MemorySessionStoreTests, UpdateRejectsMissingSession)
  {
    MemorySessionStore store;

    const auto status = store.update(make_session("missing", "user_1"));

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(MemorySessionStoreTests, RemoveByIdDeletesSessionAndIndex)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    const auto removed = store.remove_by_id("session_1");

    ASSERT_TRUE(removed.ok());
    EXPECT_TRUE(store.empty());

    const auto by_id = store.exists_by_id("session_1");
    const auto by_user = store.find_by_user_id("user_1");

    ASSERT_TRUE(by_id.ok());
    ASSERT_TRUE(by_user.ok());

    EXPECT_FALSE(by_id.value());
    EXPECT_TRUE(by_user.value().empty());
  }

  TEST(MemorySessionStoreTests, RemoveByIdRejectsMissingSession)
  {
    MemorySessionStore store;

    const auto removed = store.remove_by_id("missing");

    ASSERT_TRUE(removed.failed());
    EXPECT_EQ(removed.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(MemorySessionStoreTests, RevokeByIdMarksSessionAsRevoked)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());

    const auto revoked = store.revoke_by_id("session_1");

    ASSERT_TRUE(revoked.ok());

    const auto found = store.find_by_id("session_1");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());

    EXPECT_TRUE(found.value()->revoked());
  }

  TEST(MemorySessionStoreTests, RevokeByIdRejectsMissingSession)
  {
    MemorySessionStore store;

    const auto revoked = store.revoke_by_id("missing");

    ASSERT_TRUE(revoked.failed());
    EXPECT_EQ(revoked.error().code(), AuthErrorCode::InvalidSession);
  }

  TEST(MemorySessionStoreTests, RevokeByUserIdRevokesAllMatchingSessions)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_2", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_3", "user_2")).ok());

    const auto revoked = store.revoke_by_user_id("user_1");

    ASSERT_TRUE(revoked.ok());

    const auto user_1_sessions = store.find_by_user_id("user_1");
    const auto user_2_sessions = store.find_by_user_id("user_2");

    ASSERT_TRUE(user_1_sessions.ok());
    ASSERT_TRUE(user_2_sessions.ok());

    for (const auto &session : user_1_sessions.value())
    {
      EXPECT_TRUE(session.revoked());
    }

    ASSERT_EQ(user_2_sessions.value().size(), 1);
    EXPECT_FALSE(user_2_sessions.value().front().revoked());
  }

  TEST(MemorySessionStoreTests, RevokeByUserIdSucceedsWhenUserHasNoSessions)
  {
    MemorySessionStore store;

    const auto revoked = store.revoke_by_user_id("missing");

    EXPECT_TRUE(revoked.ok());
  }

  TEST(MemorySessionStoreTests, AllReturnsAllSessions)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_2", "user_2")).ok());

    const auto sessions = store.all();

    ASSERT_TRUE(sessions.ok());
    EXPECT_EQ(sessions.value().size(), 2);
  }

  TEST(MemorySessionStoreTests, ClearRemovesEverything)
  {
    MemorySessionStore store;

    ASSERT_TRUE(store.create(make_session("session_1", "user_1")).ok());
    ASSERT_TRUE(store.create(make_session("session_2", "user_2")).ok());

    store.clear();

    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0);
  }
} // namespace
