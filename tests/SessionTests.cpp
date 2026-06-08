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

#include <cassert>
#include <cstdint>

namespace
{
  void test_default_session_is_invalid()
  {
    const rixlib::auth::Session session;

    assert(session.id().empty());
    assert(session.user_id().empty());
    assert(session.created_at() == 0);
    assert(session.expires_at() == 0);
    assert(session.last_seen_at() == 0);
    assert(!session.revoked());
    assert(!session.valid());
  }

  void test_constructed_session_has_expected_values()
  {
    const std::int64_t created_at = 1000;
    const std::int64_t expires_at = 2000;

    const rixlib::auth::Session session{
        "session_1",
        "user_1",
        created_at,
        expires_at};

    assert(session.id() == "session_1");
    assert(session.user_id() == "user_1");
    assert(session.created_at() == created_at);
    assert(session.expires_at() == expires_at);
    assert(session.last_seen_at() == created_at);
    assert(!session.revoked());
    assert(session.valid());
  }

  void test_session_setters_update_values()
  {
    rixlib::auth::Session session;

    session.set_id("session_2");
    session.set_user_id("user_2");
    session.set_created_at(3000);
    session.set_expires_at(4000);
    session.set_last_seen_at(3500);
    session.set_revoked(true);

    assert(session.id() == "session_2");
    assert(session.user_id() == "user_2");
    assert(session.created_at() == 3000);
    assert(session.expires_at() == 4000);
    assert(session.last_seen_at() == 3500);
    assert(session.revoked());
    assert(session.valid());
  }

  void test_belongs_to_checks_user_id()
  {
    rixlib::auth::Session session;
    session.set_user_id("user_3");

    assert(session.belongs_to("user_3"));
    assert(!session.belongs_to("user_4"));
    assert(!session.belongs_to(""));
  }

  void test_session_requires_id_and_user_id_to_be_valid()
  {
    rixlib::auth::Session session;

    assert(!session.valid());

    session.set_id("session_3");
    assert(!session.valid());

    session.set_user_id("user_3");
    assert(session.valid());

    session.set_id("");
    assert(!session.valid());
  }

  void test_expired_returns_true_after_expiration()
  {
    rixlib::auth::Session session;
    session.set_expires_at(1000);

    assert(!session.expired(999));
    assert(session.expired(1000));
    assert(session.expired(1001));
  }

  void test_zero_expiration_means_not_expired()
  {
    rixlib::auth::Session session;
    session.set_expires_at(0);

    assert(!session.expired(0));
    assert(!session.expired(1000));
  }

  void test_usable_requires_valid_not_revoked_and_not_expired()
  {
    rixlib::auth::Session session{
        "session_4",
        "user_4",
        1000,
        2000};

    assert(session.usable(1500));

    session.set_revoked(true);
    assert(!session.usable(1500));

    session.set_revoked(false);
    assert(!session.usable(2000));

    session.set_id("");
    assert(!session.usable(1500));
  }
} // namespace

int main()
{
  test_default_session_is_invalid();
  test_constructed_session_has_expected_values();
  test_session_setters_update_values();
  test_belongs_to_checks_user_id();
  test_session_requires_id_and_user_id_to_be_valid();
  test_expired_returns_true_after_expiration();
  test_zero_expiration_means_not_expired();
  test_usable_requires_valid_not_revoked_and_not_expired();

  return 0;
}
