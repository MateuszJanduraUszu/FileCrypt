// password_validator.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_CRYPT_PASSWORD_VALIDATOR_HPP_
#define _FCRYPT_CRYPT_PASSWORD_VALIDATOR_HPP_
#include <string>

namespace fcrypt {
    class password_validator {
    public:
        // validates password
        static bool validate(const ::std::wstring& _Password);

    private:
        // checks if the character is a digit (0-9)
        static bool _Is_digit(const wchar_t _Ch) noexcept;

        // checks if the character is a lowercase (a-z)
        static bool _Is_lowercase(const wchar_t _Ch) noexcept;

        // checks if the character is a uppercase (A-Z)
        static bool _Is_uppercase(const wchar_t _Ch) noexcept;

        // checks if the character is a special
        static bool _Is_special(const wchar_t _Ch) noexcept;
    };
} // namespace fcrypt

#endif // _FCRYPT_CRYPT_PASSWORD_VALIDATOR_HPP_