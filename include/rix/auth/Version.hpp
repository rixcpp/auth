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
 */

#ifndef RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED
#define RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED

#include <string>

#define RIXCPP_AUTH_VERSION_MAJOR 0
#define RIXCPP_AUTH_VERSION_MINOR 2
#define RIXCPP_AUTH_VERSION_PATCH 0

#define RIXCPP_AUTH_VERSION_NUMBER       \
  ((RIXCPP_AUTH_VERSION_MAJOR * 10000) + \
   (RIXCPP_AUTH_VERSION_MINOR * 100) +   \
   RIXCPP_AUTH_VERSION_PATCH)

namespace rixlib::auth
{
  /**
   * @brief Return the rix/auth package version as a string.
   *
   * @return Version string using semantic versioning.
   */
  [[nodiscard]] std::string version();

  /**
   * @brief Return the major version component.
   *
   * @return Major version number.
   */
  [[nodiscard]] constexpr int version_major() noexcept
  {
    return RIXCPP_AUTH_VERSION_MAJOR;
  }

  /**
   * @brief Return the minor version component.
   *
   * @return Minor version number.
   */
  [[nodiscard]] constexpr int version_minor() noexcept
  {
    return RIXCPP_AUTH_VERSION_MINOR;
  }

  /**
   * @brief Return the patch version component.
   *
   * @return Patch version number.
   */
  [[nodiscard]] constexpr int version_patch() noexcept
  {
    return RIXCPP_AUTH_VERSION_PATCH;
  }

  /**
   * @brief Return the encoded integer version.
   *
   * Format:
   *
   * @code
   * major * 10000 + minor * 100 + patch
   * @endcode
   *
   * @return Encoded version number.
   */
  [[nodiscard]] constexpr int version_number() noexcept
  {
    return RIXCPP_AUTH_VERSION_NUMBER;
  }
} // namespace rixlib::auth

#endif // RIXCPP_AUTH_INCLUDE_RIX_AUTH_VERSION_HPP_INCLUDED
