// kdf.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/crypt/kdf.hpp>
#include <botan/argon2.h>
#include <cstddef>

namespace fcrypt {
    key derive_key(const ::std::wstring& _Password, const salt& _Salt) {
        // Note: The _Password (2-byte element string) is converted to _Narrow (1-byte element string)
        //       using memcpy() because we do not require specific encoding for _Password. The purpose
        //       is to pass a 1-byte element string to the argon2() fucntion.
        key _Result;
        ::std::string _Narrow(_Password.size() * sizeof(wchar_t), '\0');
        ::memcpy(_Narrow.data(), _Password.c_str(), _Narrow.size());
        try {
            ::Botan::argon2(_Result.get(), _Argon2id_traits::_Key_size, _Narrow.c_str(),
                _Narrow.size(), _Salt.get(), salt::size, nullptr, 0, nullptr, 0,
                    _Argon2id_traits::_Variant, _Argon2id_traits::_Parallelism,
                        _Argon2id_traits::_Memory_amount, _Argon2id_traits::_Iterations);
        } catch (...) {
            return key{};
        }

        return _Result;
    }
} // namespace fcrypt