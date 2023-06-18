// aes256_gcm.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_DETAILS_AES256_GCM_HPP_
#define _FCRYPT_DETAILS_AES256_GCM_HPP_
#include <fcrypt/app/utils.hpp>
#include <fcrypt/crypt/encryption_engine.hpp>
#include <fcrypt/details/cipher_context.hpp>

namespace fcrypt {
    class _Aes256_gcm : public encryption_engine { // AES-256-GCM engine
    public:
        _Aes256_gcm() noexcept;
        ~_Aes256_gcm() noexcept;

        // tries to setup the encryption process
        bool setup_encryption(const key& _Key, const iv& _Iv) noexcept override;

        // tries to setup the decryption process
        bool setup_decryption(const key& _Key, const iv& _Iv) noexcept override;
    
        // tries to encrypt the data
        bool encrypt(
            const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept override;
    
        // tries to decrypt the data
        bool decrypt(
            const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept override;
    
        // tries to complete the encryption process
        bool complete_encryption(authentication_tag& _Tag) noexcept override;
    
        // tries to complete the decryption process
        bool complete_decryption(authentication_tag& _Tag) noexcept override;

    private:
        _Cipher_context _Myctx;
    };

    [[nodiscard]] encryption_engine* _Make_aes256_gcm_engine() noexcept;
} // namespace fcrypt

#endif // _FCRYPT_DETAILS_AES256_GCM_HPP_