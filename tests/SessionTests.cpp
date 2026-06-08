/**
 *
 *  @file SessionTests.cpp
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

#include <rix/auth/Session.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::Session;

  TEST(SessionTests, DefaultSessionIsInvalid)
  {
    const Session session;

    EXPECT_TRUE(session.id().empty());
    EXPECT_TRUE(session.user_id().empty());
    EXPECT_EQ(session.created_at(), 0);
    EXPECT_EQ(session.expires_at(), 0);
    EXPECT_EQ(session.last_seen_at(), 0);
    EXPECT_FALSE(session.revoked());
    EXPECT_FALSE(session.valid());
  }

  TEST(SessionTests, ConstructedSessionStoresFields)
  {
    const Session session{
        "session_1",
        "user_1",
        1000,
        2000};

    EXPECT_EQ(session.id(), "session_1");
    EXPECT_EQ(session.user_id(), "user_1");
    EXPECT_EQ(session.created_at(), 1000);
    EXPECT_EQ(session.expires_at(), 2000);
    EXPECT_EQ(session.last_seen_at(), 1000);
    EXPECT_FALSE(session.revoked());
    EXPECT_TRUE(session.valid());
  }

  TEST(SessionTests, SettersUpdateSessionFields)
  {
    Session session;

    session.set_id("session_2");
    session.set_user_id("user_2");
    session.set_created_at(100);
    session.set_expires_at(200);
    session.set_last_seen_at(150);
    session.set_revoked(true);

    EXPECT_EQ(session.id(), "session_2");
    EXPECT_EQ(session.user_id(), "user_2");
    EXPECT_EQ(session.created_at(), 100);
    EXPECT_EQ(session.expires_at(), 200);
    EXPECT_EQ(session.last_seen_at(), 150);
    EXPECT_TRUE(session.revoked());
    EXPECT_TRUE(session.valid());
  }

  TEST(SessionTests, BelongsToReturnsTrueOnlyForMatchingUser)
  {
    const Session session{
        "session_3",
        "user_3",
        1000,
        2000};

    EXPECT_TRUE(session.belongs_to("user_3"));
    EXPECT_FALSE(session.belongs_to("user_4"));
    EXPECT_FALSE(session.belongs_to(""));
  }

  TEST(SessionTests, ExpiredReturnsFalseBeforeExpiration)
  {
    const Session session{
        "session_4",
        "user_4",
        1000,
        2000};

    EXPECT_FALSE(session.expired(1000));
    EXPECT_FALSE(session.expired(1999));
  }

  TEST(SessionTests, ExpiredReturnsTrueAtAndAfterExpiration)
  {
    const Session session{
        "session_5",
        "user_5",
        1000,
        2000};

    EXPECT_TRUE(session.expired(2000));
    EXPECT_TRUE(session.expired(2001));
  }

  TEST(SessionTests, ZeroExpirationDoesNotExpire)
  {
    const Session session{
        "session_6",
        "user_6",
        1000,
        0};

    EXPECT_FALSE(session.expired(1000));
    EXPECT_FALSE(session.expired(999999));
  }

  TEST(SessionTests, UsableRequiresValidNotRevokedAndNotExpired)
  {
    Session session{
        "session_7",
        "user_7",
        1000,
        2000};

    EXPECT_TRUE(session.usable(1500));

    session.set_revoked(true);

    EXPECT_FALSE(session.usable(1500));

    session.set_revoked(false);

    EXPECT_FALSE(session.usable(2000));
  }

  TEST(SessionTests, RevokeMarksSessionAsRevoked)
  {
    Session session{
        "session_8",
        "user_8",
        1000,
        2000};

    EXPECT_FALSE(session.revoked());

    session.revoke();

    EXPECT_TRUE(session.revoked());
    EXPECT_FALSE(session.usable(1500));
  }

  TEST(SessionTests, RefreshUpdatesExpirationAndLastSeen)
  {
    Session session{
        "session_9",
        "user_9",
        1000,
        2000};

    session.refresh(1500, 3600);

    EXPECT_EQ(session.last_seen_at(), 1500);
    EXPECT_EQ(session.expires_at(), 5100);
    EXPECT_TRUE(session.usable(5000));
    EXPECT_FALSE(session.usable(5100));
  }

  TEST(SessionTests, RefreshableRequiresValidNotRevokedAndNotExpired)
  {
    Session session{
        "session_10",
        "user_10",
        1000,
        2000};

    EXPECT_TRUE(session.refreshable(1500));

    session.set_revoked(true);

    EXPECT_FALSE(session.refreshable(1500));

    session.set_revoked(false);

    EXPECT_FALSE(session.refreshable(2000));
  }

  TEST(SessionTests, MissingIdMakesSessionInvalid)
  {
    const Session session{
        "",
        "user_11",
        1000,
        2000};

    EXPECT_FALSE(session.valid());
  }

  TEST(SessionTests, MissingUserIdMakesSessionInvalid)
  {
    const Session session{
        "session_11",
        "",
        1000,
        2000};

    EXPECT_FALSE(session.valid());
  }
} // namespace
