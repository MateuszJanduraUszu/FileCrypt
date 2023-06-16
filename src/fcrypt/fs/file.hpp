// file.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_FS_FILE_HPP_
#define _FCRYPT_FS_FILE_HPP_
#include <fcrypt/app/utils.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace fcrypt {
    using path = ::std::filesystem::path;

    enum class move_direction : bool { backward, forward };

    class file {
    public:
        explicit file(const path& _Target);
        ~file() noexcept;

        // checks if any file is open
        bool is_open() const noexcept;

        // closes the file
        void close() noexcept;

        // tries to read _Count bytes from the file
        size_t read(byte_t* const _Buf, const size_t _Count) noexcept;

        // tries to write _Bytes to the file
        bool write(const byte_string_view _Bytes) noexcept;

        // tries to change the file pointer position
        bool seek(const uint64_t _New_pos) noexcept;

        // tries to move forward/backward the file pointer
        bool move(const uint64_t _Off, const move_direction _Direction) noexcept;

        // returns the file pointer position
        const uint64_t tell() const noexcept;

        // returns the file size
        uint64_t size() const noexcept;

        // tries to resize the file
        bool resize(const uint64_t _New_size) noexcept;

    private:
        // tries to open a file
        [[nodiscard]] static void* _Open(const path& _Target);

        // tries to read some bytes from a file
        static size_t _Read_bytes(void* const _Handle, byte_t* const _Buf, const size_t _Count) noexcept;
        
        // tries to write some bytes to a file
        static bool _Write_bytes(void* const _Handle, const byte_string_view _Bytes) noexcept;

        // tries to change the file pointer position
        static bool _Seek(void* const _Handle, const uint64_t _New_pos) noexcept;

        void* _Myhandle;
        uint64_t _Myoff;
    };
} // namespace fcrypt

#endif // _FCRYPT_FS_FILE_HPP_