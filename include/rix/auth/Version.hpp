/**
 *
 *  @file Version.hpp
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
 *  Version information for rix/auth.
 *
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED

#include <string>

/// Major version component of rix/auth.
#define RIXCPP_AUTH_VERSION_MAJOR 0

/// Minor version component of rix/auth.
#define RIXCPP_AUTH_VERSION_MINOR 1

/// Patch version component of rix/auth.
#define RIXCPP_AUTH_VERSION_PATCH 0

/// Encoded rix/auth version: major * 10000 + minor * 100 + patch.
#define RIXCPP_AUTH_VERSION \
  (RIXCPP_AUTH_VERSION_MAJOR * 10000 + RIXCPP_AUTH_VERSION_MINOR * 100 + RIXCPP_AUTH_VERSION_PATCH)

namespace rixlib::auth
{
  /**
   * @brief Return the rix/auth package version as a string.
   *
   * The returned value follows semantic versioning:
   *
   * @code
   *  major.minor.patch
   * @endcode
   *
   * Example:
   *
   * @code
   *  std::string current = rixlib::auth::version();
   * @endcode
   *
   * @return The package version, for example "0.1.0".
   */
  [[nodiscard]] std::string version();

  /**
   * @brief Return the major version component.
   *
   * @return The major version number.
   */
  [[nodiscard]] constexpr int version_major() noexcept
  {
    return RIXCPP_AUTH_VERSION_MAJOR;
  }

  /**
   * @brief Return the minor version component.
   *
   * @return The minor version number.
   */
  [[nodiscard]] constexpr int version_minor() noexcept
  {
    return RIXCPP_AUTH_VERSION_MINOR;
  }

  /**
   * @brief Return the patch version component.
   *
   * @return The patch version number.
   */
  [[nodiscard]] constexpr int version_patch() noexcept
  {
    return RIXCPP_AUTH_VERSION_PATCH;
  }

  /**
   * @brief Return the encoded integer version.
   *
   * The encoded version uses the following format:
   *
   * @code
   *  major * 10000 + minor * 100 + patch
   * @endcode
   *
   * For version 0.1.0, this returns 100.
   *
   * @return The encoded version integer.
   */
  [[nodiscard]] constexpr int version_number() noexcept
  {
    return RIXCPP_AUTH_VERSION;
  }
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED
