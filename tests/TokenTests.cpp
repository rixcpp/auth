/**
 *
 *  @file TokenTests.cpp
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

#include <rix/auth/Token.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::Token;

  TEST(TokenTests, DefaultTokenIsInvalid)
  {
    const Token token;

    EXPECT_TRUE(token.value().empty());
    EXPECT_TRUE(token.user_id().empty());
    EXPECT_TRUE(token.issuer().empty());
    EXPECT_EQ(token.issued_at(), 0);
    EXPECT_EQ(token.expires_at(), 0);
    EXPECT_FALSE(token.revoked());
    EXPECT_FALSE(token.valid());
  }

  TEST(TokenTests, ConstructedTokenStoresFields)
  {
    const Token token{
        "token_1",
        "user_1",
        1000,
        2000};

    EXPECT_EQ(token.value(), "token_1");
    EXPECT_EQ(token.user_id(), "user_1");
    EXPECT_EQ(token.issued_at(), 1000);
    EXPECT_EQ(token.expires_at(), 2000);
    EXPECT_FALSE(token.revoked());
    EXPECT_TRUE(token.valid());
  }

  TEST(TokenTests, SettersUpdateTokenFields)
  {
    Token token;

    token.set_value("token_2");
    token.set_user_id("user_2");
    token.set_issuer("rix/auth");
    token.set_issued_at(100);
    token.set_expires_at(200);
    token.set_revoked(true);

    EXPECT_EQ(token.value(), "token_2");
    EXPECT_EQ(token.user_id(), "user_2");
    EXPECT_EQ(token.issuer(), "rix/auth");
    EXPECT_EQ(token.issued_at(), 100);
    EXPECT_EQ(token.expires_at(), 200);
    EXPECT_TRUE(token.revoked());
    EXPECT_TRUE(token.valid());
  }

  TEST(TokenTests, BelongsToReturnsTrueOnlyForMatchingUser)
  {
    const Token token{
        "token_3",
        "user_3",
        1000,
        2000};

    EXPECT_TRUE(token.belongs_to("user_3"));
    EXPECT_FALSE(token.belongs_to("user_4"));
    EXPECT_FALSE(token.belongs_to(""));
  }

  TEST(TokenTests, MatchesReturnsTrueOnlyForMatchingTokenValue)
  {
    const Token token{
        "token_4",
        "user_4",
        1000,
        2000};

    EXPECT_TRUE(token.matches("token_4"));
    EXPECT_FALSE(token.matches("token_5"));
    EXPECT_FALSE(token.matches(""));
  }

  TEST(TokenTests, ExpiredReturnsFalseBeforeExpiration)
  {
    const Token token{
        "token_5",
        "user_5",
        1000,
        2000};

    EXPECT_FALSE(token.expired(1000));
    EXPECT_FALSE(token.expired(1999));
  }

  TEST(TokenTests, ExpiredReturnsTrueAtAndAfterExpiration)
  {
    const Token token{
        "token_6",
        "user_6",
        1000,
        2000};

    EXPECT_TRUE(token.expired(2000));
    EXPECT_TRUE(token.expired(2001));
  }

  TEST(TokenTests, ZeroExpirationDoesNotExpire)
  {
    const Token token{
        "token_7",
        "user_7",
        1000,
        0};

    EXPECT_FALSE(token.expired(1000));
    EXPECT_FALSE(token.expired(999999));
  }

  TEST(TokenTests, UsableRequiresValidNotRevokedAndNotExpired)
  {
    Token token{
        "token_8",
        "user_8",
        1000,
        2000};

    EXPECT_TRUE(token.usable(1500));

    token.set_revoked(true);

    EXPECT_FALSE(token.usable(1500));

    token.set_revoked(false);

    EXPECT_FALSE(token.usable(2000));
  }

  TEST(TokenTests, RevokeMarksTokenAsRevoked)
  {
    Token token{
        "token_9",
        "user_9",
        1000,
        2000};

    EXPECT_FALSE(token.revoked());

    token.revoke();

    EXPECT_TRUE(token.revoked());
    EXPECT_FALSE(token.usable(1500));
  }

  TEST(TokenTests, MissingValueMakesTokenInvalid)
  {
    const Token token{
        "",
        "user_10",
        1000,
        2000};

    EXPECT_FALSE(token.valid());
  }

  TEST(TokenTests, MissingUserIdMakesTokenInvalid)
  {
    const Token token{
        "token_10",
        "",
        1000,
        2000};

    EXPECT_FALSE(token.valid());
  }
} // namespace
