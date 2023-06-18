// cipher_context.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_DETAILS_CIPHER_CONTEXT_HPP_
#define _FCRYPT_DETAILS_CIPHER_CONTEXT_HPP_
#include <fcrypt/app/utils.hpp>
#include <cstddef>
#include <openssl/evp.h>

namespace fcrypt {
    class _Cipher_context {
    public:
        _Cipher_context() noexcept;
        ~_Cipher_context() noexcept;

        static constexpr size_t _Tag_size = 16; // same as authentication_tag::size

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
} // namespace fcrypt

#endif // _FCRYPT_DETAILS_CIPHER_CONTEXT_HPP_