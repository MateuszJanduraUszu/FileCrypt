// cipher_context.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/details/cipher_context.hpp>

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
} // namespace fcrypt