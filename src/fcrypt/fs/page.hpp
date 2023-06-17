// page.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_FS_PAGE_HPP_
#define _FCRYPT_FS_PAGE_HPP_
#include <fcrypt/app/utils.hpp>
#include <fcrypt/crypt/encryption_engine.hpp>
#include <fcrypt/fs/file.hpp>
#include <cstddef>

namespace fcrypt {
    class page { // stores a single file page
    public:
        page() noexcept;
        page(const page& _Other) noexcept;
        page(page&& _Other) noexcept;
        ~page() noexcept;

        page& operator=(const page& _Other) noexcept;
        page& operator=(page&& _Other) noexcept;

        static constexpr size_t size = 4096;

        // returns the page's usage
        const size_t usage() const noexcept;

        // changes the page's usage
        void usage(const size_t _New_usage) noexcept;

        // returns a mutable pointer to the page's data
        byte_t* data() noexcept;

        // returns a non-mutable pointer to the page's data
        const byte_t* data() const noexcept;

    private:
        // copies another's page data
        void _Copy_data(const byte_t (&_Data)[size]) noexcept;
    
        // moves another's page data
        void _Move_data(byte_t (&_Data)[size]) noexcept;

        byte_t _Mydata[size];
        size_t _Myusage;
    };

    class page_encryption_manager {
    public:
        explicit page_encryption_manager(encryption_engine& _Engine) noexcept;
        ~page_encryption_manager() noexcept;

        page_encryption_manager(const page_encryption_manager&) = delete;
        page_encryption_manager& operator=(const page_encryption_manager&) = delete;

        // tries to encrypt the specified page
        bool encrypt(page& _Page) noexcept;

        // tries to decrypt the specified page
        bool decrypt(page& _Page) noexcept;

    private:
        encryption_engine& _Myeng;
    };

    class page_iterator { // iterates through all pages
    public:
        explicit page_iterator(file& _File) noexcept;
        ~page_iterator() noexcept;

        // returns the current page
        const page& current_page() const noexcept;
    
        // returns a reference to the file where the pages belong to
        file& source() noexcept;

        // resets the file pointer
        void reset() noexcept;

        // advances the iterator
        bool next() noexcept;

        // moves back _Mypage.usage() bytes
        void move_back() noexcept;

    private:
        file& _Myfile;
        page _Mypage;
    };
} // namespace fcrypt

#endif // _FCRYPT_FS_PAGE_HPP_