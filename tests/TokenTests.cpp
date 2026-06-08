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

#include <cassert>
#include <cstdint>

namespace
{
  void test_default_token_is_invalid()
  {
    const rixlib::auth::Token token;

    assert(token.value().empty());
    assert(token.user_id().empty());
    assert(token.issuer().empty());
    assert(token.issued_at() == 0);
    assert(token.expires_at() == 0);
    assert(!token.revoked());
    assert(!token.valid());
  }

  void test_constructed_token_has_expected_values()
  {
    const std::int64_t issued_at = 1000;
    const std::int64_t expires_at = 2000;

    const rixlib::auth::Token token{
        "token_value",
        "user_1",
        issued_at,
        expires_at};

    assert(token.value() == "token_value");
    assert(token.user_id() == "user_1");
    assert(token.issuer().empty());
    assert(token.issued_at() == issued_at);
    assert(token.expires_at() == expires_at);
    assert(!token.revoked());
    assert(token.valid());
  }

  void test_token_setters_update_values()
  {
    rixlib::auth::Token token;

    token.set_value("token_2");
    token.set_user_id("user_2");
    token.set_issuer("rix/auth");
    token.set_issued_at(3000);
    token.set_expires_at(4000);
    token.set_revoked(true);

    assert(token.value() == "token_2");
    assert(token.user_id() == "user_2");
    assert(token.issuer() == "rix/auth");
    assert(token.issued_at() == 3000);
    assert(token.expires_at() == 4000);
    assert(token.revoked());
    assert(token.valid());
  }

  void test_belongs_to_checks_user_id()
  {
    rixlib::auth::Token token;
    token.set_user_id("user_3");

    assert(token.belongs_to("user_3"));
    assert(!token.belongs_to("user_4"));
    assert(!token.belongs_to(""));
  }

  void test_matches_checks_token_value()
  {
    rixlib::auth::Token token;
    token.set_value("secret-token");

    assert(token.matches("secret-token"));
    assert(!token.matches("other-token"));
    assert(!token.matches(""));
  }

  void test_token_requires_value_and_user_id_to_be_valid()
  {
    rixlib::auth::Token token;

    assert(!token.valid());

    token.set_value("token_3");
    assert(!token.valid());

    token.set_user_id("user_3");
    assert(token.valid());

    token.set_value("");
    assert(!token.valid());
  }

  void test_expired_returns_true_after_expiration()
  {
    rixlib::auth::Token token;
    token.set_expires_at(1000);

    assert(!token.expired(999));
    assert(token.expired(1000));
    assert(token.expired(1001));
  }

  void test_zero_expiration_means_not_expired()
  {
    rixlib::auth::Token token;
    token.set_expires_at(0);

    assert(!token.expired(0));
    assert(!token.expired(1000));
  }

  void test_usable_requires_valid_not_revoked_and_not_expired()
  {
    rixlib::auth::Token token{
        "token_4",
        "user_4",
        1000,
        2000};

    assert(token.usable(1500));

    token.set_revoked(true);
    assert(!token.usable(1500));

    token.set_revoked(false);
    assert(!token.usable(2000));

    token.set_value("");
    assert(!token.usable(1500));
  }
} // namespace

int main()
{
  test_default_token_is_invalid();
  test_constructed_token_has_expected_values();
  test_token_setters_update_values();
  test_belongs_to_checks_user_id();
  test_matches_checks_token_value();
  test_token_requires_value_and_user_id_to_be_valid();
  test_expired_returns_true_after_expiration();
  test_zero_expiration_means_not_expired();
  test_usable_requires_valid_not_revoked_and_not_expired();

  return 0;
}
