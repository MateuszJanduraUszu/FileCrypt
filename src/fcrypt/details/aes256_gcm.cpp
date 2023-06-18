// aes256_gcm.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/details/aes256_gcm.hpp>

namespace fcrypt {
    _Aes256_gcm::_Aes256_gcm() noexcept : _Myctx() {}

    _Aes256_gcm::~_Aes256_gcm() noexcept {}

    bool _Aes256_gcm::setup_encryption(const key& _Key, const iv& _Iv) noexcept {
        if (!_Key.valid() || !_Iv.valid() || !_Myctx._Valid()) {
            return false;
        }

        return ::EVP_EncryptInit_ex(
            _Myctx._Get(), ::EVP_aes_256_gcm(), nullptr, _Key.get(), _Iv.get()) != 0;
    }

    bool _Aes256_gcm::setup_decryption(const key& _Key, const iv& _Iv) noexcept {
        if (!_Key.valid() || !_Iv.valid() || !_Myctx._Valid()) {
            return false;
        }

        return ::EVP_DecryptInit_ex(
            _Myctx._Get(), ::EVP_aes_256_gcm(), nullptr, _Key.get(), _Iv.get()) != 0;
    }

    bool _Aes256_gcm::encrypt(
        const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept {
        int _Out = 0; // encrypted bytes (unused)
        return ::EVP_EncryptUpdate(_Myctx._Get(), _Buf, &_Out, _Data, static_cast<int>(_Size)) != 0;
    }

    bool _Aes256_gcm::decrypt(
        const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept {
        int _Out = 0; // decrypted bytes (unused)
        return ::EVP_DecryptUpdate(_Myctx._Get(), _Buf, &_Out, _Data, static_cast<int>(_Size)) != 0;
    }

    bool _Aes256_gcm::complete_encryption(authentication_tag& _Tag) noexcept {
        int _Out = 0; // encrypted bytes (unused)
        if (::EVP_EncryptFinal_ex(_Myctx._Get(), nullptr, &_Out) == 0) {
            return false;
        }

        return _Myctx._Get_tag(_Tag.get());
    }

    bool _Aes256_gcm::complete_decryption(authentication_tag& _Tag) noexcept {
        if (!_Myctx._Set_tag(_Tag.get())) {
            return false;
        }

        int _Out = 0; // decrypted bytes (unused)
        return ::EVP_DecryptFinal_ex(_Myctx._Get(), nullptr, &_Out) != 0;
    }

    [[nodiscard]] encryption_engine* _Make_aes256_gcm_engine() noexcept {
        return new _Aes256_gcm();
    }
} // namespace fcrypt