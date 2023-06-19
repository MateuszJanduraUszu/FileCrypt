// encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_
#define _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_
#include <fcrypt/app/utils.hpp>
#include <cstddef>

namespace fcrypt {
    using key                = _Secure_buffer<32>;
    using iv                 = _Secure_buffer<12>;
    using authentication_tag = _Secure_buffer<16>;

    // Note: Currently, we support the AES-256-GCM encryption engine only. However, we keep
    //       the "encryption_enigne" as an abstract class to allow for future expansion
    //       and the addition of other encryption engines if needed.

    class __declspec(novtable) encryption_engine { // base class for all encryption engines
    public:
        encryption_engine() noexcept;
        virtual ~encryption_engine() noexcept;

        enum id : unsigned char {
            none       = 0x00,
            aes256_gcm = 0xAE
        };

        virtual bool setup_encryption(const key&, const iv&) noexcept                   = 0;
        virtual bool setup_decryption(const key&, const iv&) noexcept                   = 0;
        virtual bool encrypt(const byte_t* const, const size_t, byte_t* const) noexcept = 0;
        virtual bool decrypt(const byte_t* const, const size_t, byte_t* const) noexcept = 0;
        virtual bool complete_encryption(authentication_tag&) noexcept                  = 0;
        virtual bool complete_decryption(authentication_tag&) noexcept                  = 0;
    };

    [[nodiscard]] encryption_engine* make_encryption_engine(const encryption_engine::id _Id) noexcept;
} // namespace fcrypt

#endif // _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_