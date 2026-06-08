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

#include <rix/auth/PasswordHasher.hpp>

#include <cassert>
#include <string>

namespace
{
  void test_default_min_password_length_is_eight()
  {
    const rixlib::auth::PasswordHasher hasher;

    assert(hasher.min_password_length() == 8);
  }

  void test_set_min_password_length_updates_policy()
  {
    rixlib::auth::PasswordHasher hasher;

    hasher.set_min_password_length(12);

    assert(hasher.min_password_length() == 12);
    assert(!hasher.accepts("short123"));
    assert(hasher.accepts("long-password"));
  }

  void test_accepts_password_when_length_is_valid()
  {
    const rixlib::auth::PasswordHasher hasher;

    assert(hasher.accepts("secret123"));
    assert(!hasher.accepts("short"));
    assert(!hasher.accepts(""));
  }

  void test_hash_fails_when_password_is_too_short()
  {
    const rixlib::auth::PasswordHasher hasher;

    const auto result = hasher.hash("short");

    assert(result.failed());
    assert(result.error().code() == rixlib::auth::AuthErrorCode::InvalidPassword);
  }

  void test_hash_succeeds_when_password_is_valid()
  {
    const rixlib::auth::PasswordHasher hasher;

    const auto result = hasher.hash("secret123");

    assert(result.ok());
    assert(!result.value().empty());
  }

  void test_verify_returns_true_for_matching_password()
  {
    const rixlib::auth::PasswordHasher hasher;

    const auto result = hasher.hash("secret123");

    assert(result.ok());
    assert(hasher.verify("secret123", result.value()));
  }

  void test_verify_returns_false_for_wrong_password()
  {
    const rixlib::auth::PasswordHasher hasher;

    const auto result = hasher.hash("secret123");

    assert(result.ok());
    assert(!hasher.verify("another-password", result.value()));
  }

  void test_verify_returns_false_for_empty_hash()
  {
    const rixlib::auth::PasswordHasher hasher;

    assert(!hasher.verify("secret123", ""));
  }

  void test_same_password_produces_same_hash_for_current_basic_hasher()
  {
    const rixlib::auth::PasswordHasher hasher;

    const auto first = hasher.hash("secret123");
    const auto second = hasher.hash("secret123");

    assert(first.ok());
    assert(second.ok());
    assert(first.value() == second.value());
  }
} // namespace

int main()
{
  test_default_min_password_length_is_eight();
  test_set_min_password_length_updates_policy();
  test_accepts_password_when_length_is_valid();
  test_hash_fails_when_password_is_too_short();
  test_hash_succeeds_when_password_is_valid();
  test_verify_returns_true_for_matching_password();
  test_verify_returns_false_for_wrong_password();
  test_verify_returns_false_for_empty_hash();
  test_same_password_produces_same_hash_for_current_basic_hasher();

  return 0;
}
