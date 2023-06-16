// encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_
#define _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_
#include <fcrypt/app/utils.hpp>
#include <cstddef>
#include <openssl/evp.h>

namespace fcrypt {
    using key                = _Secure_buffer<32>;
    using iv                 = _Secure_buffer<12>;
    using authentication_tag = _Secure_buffer<16>;

    class _Cipher_context {
    public:
        _Cipher_context() noexcept;
        ~_Cipher_context() noexcept;

        static constexpr size_t _Tag_size = authentication_tag::size;

        // checks if the context is valid
        bool _Valid() const noexcept;

        // returns a pointer to the context
        EVP_CIPHER_CTX* _Get() noexcept;

        // changes the authentication tag associated with the context
        bool _Get_tag(byte_t* const _Tag) noexcept;

        // returns the authentication tag associated with the context
        bool _Set_tag(byte_t* const _New_tag) noexcept;

    private:
        EVP_CIPHER_CTX* _Myptr;
    };

    class encryption_engine { // AES-256-GCM encryption engine
    public:
        encryption_engine() noexcept;
        ~encryption_engine() noexcept;
    
        // tries to setup the encryption process
        bool setup_encryption(const key& _Key, const iv& _Iv) noexcept;

        // tries to setup the decryption process
        bool setup_decryption(const key& _Key, const iv& _Iv) noexcept;
    
        // tries to encrypt the data
        bool encrypt(const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept;
    
        // tries to decrypt the data
        bool decrypt(const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept;
    
        // tries to complete the encryption process
        bool complete_encryption(authentication_tag& _Tag) noexcept;
    
        // tries to complete the decryption process
        bool complete_decryption(authentication_tag& _Tag) noexcept;

    private:
        _Cipher_context _Myctx;
    };
} // namespace fcrypt

#endif // _FCRYPT_CRYPT_ENCRYPTION_ENGINE_HPP_