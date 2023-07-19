// password_validator.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/crypt/password_validator.hpp>

namespace fcrypt {
    bool password_validator::_Is_digit(const wchar_t _Ch) noexcept {
        return _Ch >= wchar_t{48} && _Ch <= wchar_t{57};
    }

    bool password_validator::_Is_lowercase(const wchar_t _Ch) noexcept {
        return _Ch >= wchar_t{97} && _Ch <= wchar_t{122};
    }

    bool password_validator::_Is_uppercase(const wchar_t _Ch) noexcept {
        return _Ch >= wchar_t{65} && _Ch <= wchar_t{90};
    }

    bool password_validator::_Is_special(const wchar_t _Ch) noexcept {
        return (_Ch >= wchar_t{33} && _Ch <= wchar_t{47})
            || (_Ch >= wchar_t{58} && _Ch <= wchar_t{64})
            || (_Ch >= wchar_t{91} && _Ch <= wchar_t{96})
            || (_Ch >= wchar_t{123} && _Ch <= wchar_t{126});
    }

    bool password_validator::validate(const ::std::wstring& _Password) {
        if (_Password.size() < 8) { // must contain at least 8 characters
            return false;
        }

        bool _Has_digit     = false;
        bool _Has_lowercase = false;
        bool _Has_uppercase = false;
        bool _Has_special   = false;
        const auto _Valid   = [&]() noexcept {
            // all requirements must be met
            return _Has_digit && _Has_lowercase && _Has_uppercase && _Has_special;
        };
        for (const wchar_t _Ch : _Password) {
            if (_Valid()) { // all requirements already met, break
                return true;
            }

            if (!_Has_digit) { // search for a digit
                if (_Is_digit(_Ch)) {
                    _Has_digit = true;
                    continue;
                }
            }

            if (!_Has_lowercase) { // search for a lowercase
                if (_Is_lowercase(_Ch)) {
                    _Has_lowercase = true;
                    continue;
                }
            }

            if (!_Has_uppercase) { // search for a uppercase
                if (_Is_uppercase(_Ch)) {
                    _Has_uppercase = true;
                    continue;
                }
            }

            if (!_Has_special) { // search for a special
                if (_Is_special(_Ch)) {
                    _Has_special = true;
                    continue;
                }
            }
        }

        return _Valid();
    }
} // namespace fcrypt