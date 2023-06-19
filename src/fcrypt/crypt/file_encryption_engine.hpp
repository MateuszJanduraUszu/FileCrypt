// file_encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_CRYPT_FILE_ENCRYPTION_ENGINE_HPP_
#define _FCRYPT_CRYPT_FILE_ENCRYPTION_ENGINE_HPP_
#include <fcrypt/app/utils.hpp>
#include <fcrypt/crypt/encryption_engine.hpp>
#include <fcrypt/crypt/kdf.hpp>
#include <fcrypt/fs/file.hpp>
#include <fcrypt/fs/page.hpp>
#include <cstddef>

namespace fcrypt {
    class metadata {
    public:
        metadata() noexcept;
        ~metadata() noexcept;

        metadata(const metadata&) = delete;
        metadata& operator=(const metadata&) = delete;

        static constexpr size_t size = sizeof(encryption_engine::id)
            + iv::size + authentication_tag::size + salt::size;

        // returns the associated encryption engine ID
        encryption_engine::id& get_encryption_engine_id() noexcept;

        // returns the associated IV
        iv& get_iv() noexcept;

        // returns the associated authentication tag
        authentication_tag& get_tag() noexcept;

        // returns the associated salt
        salt& get_salt() noexcept;

        // generates a new metadata
        void generate() noexcept;

        // tries to extract a metadata from the file
        bool extract(file& _File) noexcept;

        // tries to safe the metadata to the file
        bool save(file& _File) noexcept;

    private:
        static constexpr size_t _Iv_offset   = sizeof(encryption_engine::id);
        static constexpr size_t _Tag_offset  = _Iv_offset + iv::size;
        static constexpr size_t _Salt_offset = _Tag_offset + authentication_tag::size;

        encryption_engine::id _Myeeid;
        iv _Myiv;
        authentication_tag _Mytag;
        salt _Mysalt;
    };

    class file_encryption_engine {
    public:
        explicit file_encryption_engine(file& _File, encryption_engine* const _Engine) noexcept;
        ~file_encryption_engine() noexcept;

        enum error : unsigned char {
            success,
            invalid_tag,
            failure
        };

        // tries to encrypt the file
        error encrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept;

        // tries to decrypt the file
        error decrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept;

    private:
        page_iterator _Myiter;
        encryption_engine* _Myeng;
    };
} // namespace fcrypt

#endif // _FCRYPT_CRYPT_FILE_ENCRYPTION_ENGINE_HPP_