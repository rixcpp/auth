/**
 *
 *  @file PasswordHasherTests.cpp
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

#include <rix/auth/AuthConfig.hpp>
#include <rix/auth/AuthError.hpp>
#include <rix/auth/PasswordHasher.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::AuthConfig;
  using rixlib::auth::AuthErrorCode;
  using rixlib::auth::PasswordHasher;

  TEST(PasswordHasherTests, DefaultHasherAcceptsPasswordsWithMinimumLength)
  {
    const PasswordHasher hasher;

    EXPECT_FALSE(hasher.accepts(""));
    EXPECT_FALSE(hasher.accepts("short"));
    EXPECT_TRUE(hasher.accepts("password"));
    EXPECT_TRUE(hasher.accepts("very-strong-password"));
  }

  TEST(PasswordHasherTests, ConfigConstructorUsesConfiguredMinimumLength)
  {
    AuthConfig config;
    config.set_min_password_length(12);

    const PasswordHasher hasher{config};

    EXPECT_FALSE(hasher.accepts("password"));
    EXPECT_TRUE(hasher.accepts("long-password"));
  }

  TEST(PasswordHasherTests, HashRejectsPasswordBelowMinimumLength)
  {
    PasswordHasher hasher;
    hasher.set_min_password_length(12);

    const auto result = hasher.hash("short");

    ASSERT_TRUE(result.failed());
    EXPECT_EQ(result.error().code(), AuthErrorCode::InvalidPassword);
  }

  TEST(PasswordHasherTests, HashAcceptsPasswordThatSatisfiesPolicy)
  {
    const PasswordHasher hasher;

    const auto result = hasher.hash("correct-password");

    ASSERT_TRUE(result.ok());
    EXPECT_FALSE(result.value().empty());
    EXPECT_NE(result.value(), "correct-password");
  }

  TEST(PasswordHasherTests, HashProducesEncodedPasswordHash)
  {
    const PasswordHasher hasher;

    const auto result = hasher.hash("correct-password");

    ASSERT_TRUE(result.ok());
    EXPECT_NE(result.value().find("rix-auth$"), std::string::npos);
  }

  TEST(PasswordHasherTests, VerifyAcceptsMatchingPassword)
  {
    const PasswordHasher hasher;

    const auto hash = hasher.hash("correct-password");

    ASSERT_TRUE(hash.ok());
    EXPECT_TRUE(hasher.verify("correct-password", hash.value()));
  }

  TEST(PasswordHasherTests, VerifyRejectsWrongPassword)
  {
    const PasswordHasher hasher;

    const auto hash = hasher.hash("correct-password");

    ASSERT_TRUE(hash.ok());
    EXPECT_FALSE(hasher.verify("wrong-password", hash.value()));
  }

  TEST(PasswordHasherTests, VerifyRejectsEmptyHash)
  {
    const PasswordHasher hasher;

    EXPECT_FALSE(hasher.verify("correct-password", ""));
  }

  TEST(PasswordHasherTests, VerifyRejectsPasswordBelowPolicy)
  {
    PasswordHasher hasher;
    hasher.set_min_password_length(12);

    const auto hash = hasher.hash("long-password");

    ASSERT_TRUE(hash.ok());
    EXPECT_FALSE(hasher.verify("short", hash.value()));
  }

  TEST(PasswordHasherTests, SamePasswordCanBeVerifiedFromStoredHash)
  {
    const PasswordHasher hasher;

    const auto hash = hasher.hash("another-correct-password");

    ASSERT_TRUE(hash.ok());

    const std::string stored_hash = hash.value();

    EXPECT_TRUE(hasher.verify("another-correct-password", stored_hash));
  }

  TEST(PasswordHasherTests, DifferentHashesAreProducedForSamePassword)
  {
    const PasswordHasher hasher;

    const auto first = hasher.hash("correct-password");
    const auto second = hasher.hash("correct-password");

    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());

    EXPECT_NE(first.value(), second.value());
    EXPECT_TRUE(hasher.verify("correct-password", first.value()));
    EXPECT_TRUE(hasher.verify("correct-password", second.value()));
  }
} // namespace
