// utils.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_APP_UTILS_HPP_
#define _FCRYPT_APP_UTILS_HPP_
#include <fcrypt/app/tinywin.hpp>
#include <openssl/rand.h>
#include <string>
#include <string_view>
#include <type_traits>

namespace fcrypt {
    using byte_t           = unsigned char;
    using byte_string      = ::std::basic_string<byte_t>;
    using byte_string_view = ::std::basic_string_view<byte_t>;

    template <class _Ty>
    constexpr const _Ty _Min(const _Ty _Left, const _Ty _Right) noexcept {
        return _Left < _Right ? _Left : _Right;
    }

    inline void _Scrub_memory(void* _Ptr, const size_t _Size) noexcept {
        ::SecureZeroMemory(_Ptr, _Size);
    }

    template <size_t _Size>
    class _Secure_buffer { // auto-erasing stack-based buffer
    public:
        _Secure_buffer() noexcept : _Mydata{0} {}

        _Secure_buffer(const _Secure_buffer& _Other) noexcept : _Mydata{0} {
            if (_Other.valid()) {
                _Copy_buffer(_Other);
            }
        }

        _Secure_buffer(_Secure_buffer&& _Other) noexcept : _Mydata{0} {
            if (_Other.valid()) {
                _Move_buffer(::std::move(_Other));
            }
        }

        ~_Secure_buffer() noexcept {
            _Scrub_memory(_Mydata, _Size); // erase remaining memory
        }

        _Secure_buffer& operator=(const _Secure_buffer& _Other) noexcept {
            if (this != ::std::addressof(_Other)) {
                _Copy_buffer(_Other);
            }

            return *this;
        }

        _Secure_buffer& operator=(_Secure_buffer&& _Other) noexcept {
            if (this != ::std::addressof(_Other)) {
                _Move_buffer(::std::move(_Other));
            }

            return *this;
        }

        static constexpr size_t size = _Size;

        static _Secure_buffer generate() noexcept {
            _Secure_buffer _Result;
            ::RAND_bytes(_Result._Mydata, static_cast<int>(_Size));
            return _Result;
        }

        void set(const byte_t (&_Bytes)[_Size]) noexcept {
            // Note: Use memmove() instead of memcpy() to ensure, that _Bytes is not same as _Mybuf.
            ::memmove(_Mydata, _Bytes, _Size);
        }

        void set(const byte_string_view _Bytes) noexcept {
            if (_Bytes.size() >= _Size) { // must contains at least _Size bytes
                ::memmove(_Mydata, _Bytes.data(), _Size);
            }
        }

        byte_t* get() noexcept {
            return _Mydata;
        }

        const byte_t* get() const noexcept {
            return _Mydata;
        }

        bool valid() const noexcept {
            byte_t _Empty[_Size] = {0}; // empty buffer is invalid
            return ::memcmp(_Mydata, _Empty, _Size) != 0;
        }

    private:
        void _Copy_buffer(const _Secure_buffer& _Other) noexcept {
            ::memcpy(_Mydata, _Other._Mydata, _Size);
        }

        void _Move_buffer(_Secure_buffer&& _Other) noexcept {
            ::memcpy(_Mydata, _Other._Mydata, _Size);
            _Scrub_memory(_Other._Mydata, _Size);
        }

        byte_t _Mydata[_Size];
    };

    template <class _Ty>
    constexpr bool _Has_bits(const _Ty _Bitmask, const _Ty _Bits) noexcept {
        return (_Bitmask & _Bits) != _Ty{0};
    }

    class _Dynamic_library_handle {
    public:
        explicit _Dynamic_library_handle(const char* const _Name) : _Myptr(::LoadLibraryA(_Name)) {}
    
        ~_Dynamic_library_handle() noexcept {
            if (_Myptr) {
                ::FreeLibrary(_Myptr);
                _Myptr = nullptr;
            }
        }

        bool _Valid() const noexcept {
            return _Myptr != nullptr;
        }

        HMODULE _Get() noexcept {
            return _Myptr;
        }

    private:
        HMODULE _Myptr;
    };

    template <class _Fn>
    inline _Fn _Load_symbol(_Dynamic_library_handle& _Handle, const char* const _Symbol) noexcept {
        return _Handle._Valid() ? reinterpret_cast<_Fn>(::GetProcAddress(_Handle._Get(), _Symbol)) : nullptr;
    }
} // namespace fcrypt

#endif // _FCRYPT_APP_UTILS_HPP_