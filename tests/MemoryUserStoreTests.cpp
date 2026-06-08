/**
 *
 *  @file MemoryUserStoreTests.cpp
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
#include <rix/auth/stores/MemoryUserStore.hpp>

#include <gtest/gtest.h>

namespace
{
  using rixlib::auth::AuthErrorCode;
  using rixlib::auth::MemoryUserStore;
  using rixlib::auth::User;

  [[nodiscard]] User make_user(
      std::string id = "user_1",
      std::string email = "ada@example.com")
  {
    return User{
        std::move(id),
        std::move(email),
        "encoded-password-hash",
        1000};
  }

  TEST(MemoryUserStoreTests, StartsEmpty)
  {
    const MemoryUserStore store;

    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0);
  }

  TEST(MemoryUserStoreTests, CreateStoresUser)
  {
    MemoryUserStore store;

    const auto status = store.create(make_user());

    EXPECT_TRUE(status.ok());
    EXPECT_FALSE(store.empty());
    EXPECT_EQ(store.size(), 1);
  }

  TEST(MemoryUserStoreTests, CreateRejectsInvalidUser)
  {
    MemoryUserStore store;

    const User user;

    const auto status = store.create(user);

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::InvalidInput);
    EXPECT_TRUE(store.empty());
  }

  TEST(MemoryUserStoreTests, CreateRejectsDuplicateId)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto status = store.create(make_user("user_1", "grace@example.com"));

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::UserAlreadyExists);
  }

  TEST(MemoryUserStoreTests, CreateRejectsDuplicateEmail)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto status = store.create(make_user("user_2", "ada@example.com"));

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::UserAlreadyExists);
  }

  TEST(MemoryUserStoreTests, FindByIdReturnsStoredUser)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto found = store.find_by_id("user_1");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->id(), "user_1");
    EXPECT_EQ(found.value()->email(), "ada@example.com");
  }

  TEST(MemoryUserStoreTests, FindByIdReturnsEmptyOptionalWhenMissing)
  {
    MemoryUserStore store;

    const auto found = store.find_by_id("missing");

    ASSERT_TRUE(found.ok());
    EXPECT_FALSE(found.value().has_value());
  }

  TEST(MemoryUserStoreTests, FindByIdRejectsEmptyId)
  {
    MemoryUserStore store;

    const auto found = store.find_by_id("");

    ASSERT_TRUE(found.failed());
    EXPECT_EQ(found.error().code(), AuthErrorCode::InvalidInput);
  }

  TEST(MemoryUserStoreTests, FindByEmailReturnsStoredUser)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto found = store.find_by_email("ada@example.com");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->id(), "user_1");
    EXPECT_EQ(found.value()->email(), "ada@example.com");
  }

  TEST(MemoryUserStoreTests, FindByEmailReturnsEmptyOptionalWhenMissing)
  {
    MemoryUserStore store;

    const auto found = store.find_by_email("missing@example.com");

    ASSERT_TRUE(found.ok());
    EXPECT_FALSE(found.value().has_value());
  }

  TEST(MemoryUserStoreTests, FindByEmailRejectsEmptyEmail)
  {
    MemoryUserStore store;

    const auto found = store.find_by_email("");

    ASSERT_TRUE(found.failed());
    EXPECT_EQ(found.error().code(), AuthErrorCode::InvalidEmail);
  }

  TEST(MemoryUserStoreTests, ExistsByIdReturnsExpectedState)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto existing = store.exists_by_id("user_1");
    const auto missing = store.exists_by_id("missing");

    ASSERT_TRUE(existing.ok());
    ASSERT_TRUE(missing.ok());

    EXPECT_TRUE(existing.value());
    EXPECT_FALSE(missing.value());
  }

  TEST(MemoryUserStoreTests, ExistsByEmailReturnsExpectedState)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto existing = store.exists_by_email("ada@example.com");
    const auto missing = store.exists_by_email("missing@example.com");

    ASSERT_TRUE(existing.ok());
    ASSERT_TRUE(missing.ok());

    EXPECT_TRUE(existing.value());
    EXPECT_FALSE(missing.value());
  }

  TEST(MemoryUserStoreTests, UpdateChangesStoredUser)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    User user = make_user("user_1", "grace@example.com");
    user.set_password_hash("new-hash");
    user.set_email_verified(true);
    user.set_active(false);
    user.set_updated_at(2000);

    const auto status = store.update(user);

    ASSERT_TRUE(status.ok());

    const auto found = store.find_by_id("user_1");

    ASSERT_TRUE(found.ok());
    ASSERT_TRUE(found.value().has_value());

    EXPECT_EQ(found.value()->email(), "grace@example.com");
    EXPECT_EQ(found.value()->password_hash(), "new-hash");
    EXPECT_TRUE(found.value()->email_verified());
    EXPECT_FALSE(found.value()->active());
    EXPECT_EQ(found.value()->updated_at(), 2000);

    const auto old_email = store.exists_by_email("ada@example.com");
    const auto new_email = store.exists_by_email("grace@example.com");

    ASSERT_TRUE(old_email.ok());
    ASSERT_TRUE(new_email.ok());

    EXPECT_FALSE(old_email.value());
    EXPECT_TRUE(new_email.value());
  }

  TEST(MemoryUserStoreTests, UpdateRejectsMissingUser)
  {
    MemoryUserStore store;

    const auto status = store.update(make_user("missing", "ada@example.com"));

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::UserNotFound);
  }

  TEST(MemoryUserStoreTests, UpdateRejectsDuplicateEmailOwner)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());
    ASSERT_TRUE(store.create(make_user("user_2", "grace@example.com")).ok());

    User user = make_user("user_2", "ada@example.com");

    const auto status = store.update(user);

    ASSERT_TRUE(status.failed());
    EXPECT_EQ(status.error().code(), AuthErrorCode::UserAlreadyExists);
  }

  TEST(MemoryUserStoreTests, RemoveByIdDeletesUserAndEmailIndex)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());

    const auto removed = store.remove_by_id("user_1");

    ASSERT_TRUE(removed.ok());
    EXPECT_TRUE(store.empty());

    const auto by_id = store.exists_by_id("user_1");
    const auto by_email = store.exists_by_email("ada@example.com");

    ASSERT_TRUE(by_id.ok());
    ASSERT_TRUE(by_email.ok());

    EXPECT_FALSE(by_id.value());
    EXPECT_FALSE(by_email.value());
  }

  TEST(MemoryUserStoreTests, RemoveByIdRejectsMissingUser)
  {
    MemoryUserStore store;

    const auto removed = store.remove_by_id("missing");

    ASSERT_TRUE(removed.failed());
    EXPECT_EQ(removed.error().code(), AuthErrorCode::UserNotFound);
  }

  TEST(MemoryUserStoreTests, AllReturnsAllUsers)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());
    ASSERT_TRUE(store.create(make_user("user_2", "grace@example.com")).ok());

    const auto users = store.all();

    ASSERT_TRUE(users.ok());
    EXPECT_EQ(users.value().size(), 2);
  }

  TEST(MemoryUserStoreTests, ClearRemovesEverything)
  {
    MemoryUserStore store;

    ASSERT_TRUE(store.create(make_user("user_1", "ada@example.com")).ok());
    ASSERT_TRUE(store.create(make_user("user_2", "grace@example.com")).ok());

    store.clear();

    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0);
  }
} // namespace
