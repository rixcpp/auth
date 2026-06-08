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

#include <cassert>
#include <cstdint>
#include <string>

namespace
{
  void test_default_user_is_invalid()
  {
    const rixlib::auth::User user;

    assert(user.id().empty());
    assert(user.email().empty());
    assert(user.password_hash().empty());
    assert(!user.email_verified());
    assert(user.active());
    assert(user.created_at() == 0);
    assert(user.updated_at() == 0);
    assert(!user.valid());
  }

  void test_constructed_user_has_expected_values()
  {
    const std::int64_t created_at = 1000;

    const rixlib::auth::User user{
        "user_1",
        "ada@example.com",
        "hashed-password",
        created_at};

    assert(user.id() == "user_1");
    assert(user.email() == "ada@example.com");
    assert(user.password_hash() == "hashed-password");
    assert(user.created_at() == created_at);
    assert(user.updated_at() == created_at);
    assert(user.active());
    assert(!user.email_verified());
    assert(user.valid());
  }

  void test_user_setters_update_values()
  {
    rixlib::auth::User user;

    user.set_id("user_2");
    user.set_email("grace@example.com");
    user.set_password_hash("new-hash");
    user.set_email_verified(true);
    user.set_active(false);
    user.set_created_at(2000);
    user.set_updated_at(3000);

    assert(user.id() == "user_2");
    assert(user.email() == "grace@example.com");
    assert(user.password_hash() == "new-hash");
    assert(user.email_verified());
    assert(!user.active());
    assert(user.created_at() == 2000);
    assert(user.updated_at() == 3000);
    assert(user.valid());
  }

  void test_has_email_checks_exact_email()
  {
    rixlib::auth::User user;
    user.set_email("user@example.com");

    assert(user.has_email("user@example.com"));
    assert(!user.has_email("other@example.com"));
    assert(!user.has_email(""));
  }

  void test_user_requires_id_and_email_to_be_valid()
  {
    rixlib::auth::User user;

    assert(!user.valid());

    user.set_id("user_3");
    assert(!user.valid());

    user.set_email("user3@example.com");
    assert(user.valid());

    user.set_id("");
    assert(!user.valid());
  }
} // namespace

int main()
{
  test_default_user_is_invalid();
  test_constructed_user_has_expected_values();
  test_user_setters_update_values();
  test_has_email_checks_exact_email();
  test_user_requires_id_and_email_to_be_valid();

  return 0;
}
