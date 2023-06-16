// encryption_engine.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/crypt/encryption_engine.hpp>

namespace fcrypt {
    _Cipher_context::_Cipher_context() noexcept : _Myptr(::EVP_CIPHER_CTX_new()) {}

    _Cipher_context::~_Cipher_context() noexcept {
        if (_Myptr) {
            ::EVP_CIPHER_CTX_free(_Myptr);
            _Myptr = nullptr;
        }
    }

    bool _Cipher_context::_Valid() const noexcept {
        return _Myptr != nullptr;
    }

    EVP_CIPHER_CTX* _Cipher_context::_Get() noexcept {
        return _Myptr;
    }

    bool _Cipher_context::_Get_tag(byte_t* const _Tag) noexcept {
        return ::EVP_CIPHER_CTX_ctrl(_Myptr, EVP_CTRL_AEAD_GET_TAG, _Tag_size, _Tag) != 0;
    }

    bool _Cipher_context::_Set_tag(byte_t* const _New_tag) noexcept {
        return ::EVP_CIPHER_CTX_ctrl(_Myptr, EVP_CTRL_AEAD_SET_TAG, _Tag_size, _New_tag) != 0;
    }

    encryption_engine::encryption_engine() noexcept : _Myctx() {}

    encryption_engine::~encryption_engine() noexcept {}

    bool encryption_engine::setup_encryption(const key& _Key, const iv& _Iv) noexcept {
        if (!_Key.valid() || !_Iv.valid() || !_Myctx._Valid()) {
            return false;
        }

        return ::EVP_EncryptInit_ex(
            _Myctx._Get(), ::EVP_aes_256_gcm(), nullptr, _Key.get(), _Iv.get()) != 0;
    }

    bool encryption_engine::setup_decryption(const key& _Key, const iv& _Iv) noexcept {
        if (!_Key.valid() || !_Iv.valid() || !_Myctx._Valid()) {
            return false;
        }

        return ::EVP_DecryptInit_ex(
            _Myctx._Get(), ::EVP_aes_256_gcm(), nullptr, _Key.get(), _Iv.get()) != 0;
    }

    bool encryption_engine::encrypt(
        const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept {
        int _Out = 0; // encrypted bytes (unused)
        return ::EVP_EncryptUpdate(_Myctx._Get(), _Buf, &_Out, _Data, static_cast<int>(_Size)) != 0;
    }

    bool encryption_engine::decrypt(
        const byte_t* const _Data, const size_t _Size, byte_t* const _Buf) noexcept {
        int _Out = 0; // decrypted bytes (unused)
        return ::EVP_DecryptUpdate(_Myctx._Get(), _Buf, &_Out, _Data, static_cast<int>(_Size)) != 0;
    }

    bool encryption_engine::complete_encryption(authentication_tag& _Tag) noexcept {
        int _Out = 0; // encrypted bytes (unused)
        if (::EVP_EncryptFinal_ex(_Myctx._Get(), nullptr, &_Out) == 0) {
            return false;
        }

        return _Myctx._Get_tag(_Tag.get());
    }

    bool encryption_engine::complete_decryption(authentication_tag& _Tag) noexcept {
        if (!_Myctx._Set_tag(_Tag.get())) {
            return false;
        }

        int _Out = 0; // decrypted bytes (unused)
        return ::EVP_DecryptFinal_ex(_Myctx._Get(), nullptr, &_Out) != 0;
    }
} // namespace fcrypt