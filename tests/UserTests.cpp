/**
 *
 *  @file UserTests.cpp
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

#include <rix/auth/User.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::User;

  TEST(UserTests, DefaultUserIsInvalid)
  {
    const User user;

    EXPECT_TRUE(user.id().empty());
    EXPECT_TRUE(user.email().empty());
    EXPECT_TRUE(user.password_hash().empty());
    EXPECT_FALSE(user.email_verified());
    EXPECT_TRUE(user.active());
    EXPECT_EQ(user.created_at(), 0);
    EXPECT_EQ(user.updated_at(), 0);
    EXPECT_FALSE(user.valid());
  }

  TEST(UserTests, ConstructedUserStoresIdentityAndTimestamps)
  {
    const User user{
        "user_1",
        "ada@example.com",
        "encoded-password-hash",
        1000};

    EXPECT_EQ(user.id(), "user_1");
    EXPECT_EQ(user.email(), "ada@example.com");
    EXPECT_EQ(user.password_hash(), "encoded-password-hash");
    EXPECT_EQ(user.created_at(), 1000);
    EXPECT_EQ(user.updated_at(), 1000);
    EXPECT_TRUE(user.valid());
  }

  TEST(UserTests, SettersUpdateUserFields)
  {
    User user;

    user.set_id("user_2");
    user.set_email("grace@example.com");
    user.set_password_hash("hash");
    user.set_email_verified(true);
    user.set_active(false);
    user.set_created_at(2000);
    user.set_updated_at(3000);

    EXPECT_EQ(user.id(), "user_2");
    EXPECT_EQ(user.email(), "grace@example.com");
    EXPECT_EQ(user.password_hash(), "hash");
    EXPECT_TRUE(user.email_verified());
    EXPECT_FALSE(user.active());
    EXPECT_EQ(user.created_at(), 2000);
    EXPECT_EQ(user.updated_at(), 3000);
    EXPECT_TRUE(user.valid());
  }

  TEST(UserTests, HasIdReturnsTrueOnlyForMatchingId)
  {
    const User user{
        "user_3",
        "linus@example.com",
        "hash",
        1000};

    EXPECT_TRUE(user.has_id("user_3"));
    EXPECT_FALSE(user.has_id("user_4"));
    EXPECT_FALSE(user.has_id(""));
  }

  TEST(UserTests, HasEmailReturnsTrueOnlyForMatchingEmail)
  {
    const User user{
        "user_4",
        "bjarne@example.com",
        "hash",
        1000};

    EXPECT_TRUE(user.has_email("bjarne@example.com"));
    EXPECT_FALSE(user.has_email("other@example.com"));
    EXPECT_FALSE(user.has_email(""));
  }

  TEST(UserTests, MissingIdMakesUserInvalid)
  {
    const User user{
        "",
        "ada@example.com",
        "hash",
        1000};

    EXPECT_FALSE(user.valid());
  }

  TEST(UserTests, MissingEmailMakesUserInvalid)
  {
    const User user{
        "user_5",
        "",
        "hash",
        1000};

    EXPECT_FALSE(user.valid());
  }

  TEST(UserTests, MissingPasswordHashMakesUserInvalid)
  {
    const User user{
        "user_6",
        "ada@example.com",
        "",
        1000};

    EXPECT_FALSE(user.valid());
  }
} // namespace
