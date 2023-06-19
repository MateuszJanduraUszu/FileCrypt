// kdf.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_KDF_HPP_
#define _FCRYPT_KDF_HPP_
#include <fcrypt/app/utils.hpp>
#include <fcrypt/crypt/encryption_engine.hpp>
#include <string>

namespace fcrypt {
    using salt = _Secure_buffer<16>;

    struct _Argon2id_traits {
        static constexpr uint8_t _Variant      = 2; // Argon2 variant (Argon2id is 2)
        static constexpr size_t _Key_size      = 32; // 256-bit key
        static constexpr size_t _Parallelism   = 1; // number of threads
        static constexpr size_t _Memory_amount = 16384; // memory amount in Kb
        static constexpr size_t _Iterations    = 8; // number of iterations
    };

    key derive_key(const ::std::wstring& _Password, const salt& _Salt);
} // namespace fcrypt

#endif // _FCRYPT_KDF_HPP_