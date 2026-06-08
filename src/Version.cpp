/**
 *
 *  @file Version.cpp
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

#include <rix/auth/Version.hpp>

namespace rixlib::auth
{
  std::string version()
  {
    return std::to_string(RIXCPP_AUTH_VERSION_MAJOR) + "." +
           std::to_string(RIXCPP_AUTH_VERSION_MINOR) + "." +
           std::to_string(RIXCPP_AUTH_VERSION_PATCH);
  }
} // namespace rixlib::auth
