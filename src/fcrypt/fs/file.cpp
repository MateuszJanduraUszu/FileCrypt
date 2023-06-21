// file.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/fs/file.hpp>
#include <Windows.h>

namespace fcrypt {
    file::file(const path& _Target) : _Myhandle(_Open(_Target)), _Myoff(0) {}

    file::~file() noexcept {
        close();
    }

    [[nodiscard]] void* file::_Open(const path& _Target) {
        return ::CreateFileW(_Target.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    size_t file::_Read_bytes(void* const _Handle, byte_t* const _Buf, const size_t _Count) noexcept {
        unsigned long _Read = 0;
        return ::ReadFile(_Handle, _Buf, static_cast<unsigned long>(_Count), &_Read, nullptr) != 0
            ? static_cast<size_t>(_Read) : 0;
    }

    bool file::_Write_bytes(void* const _Handle, const byte_string_view _Bytes) noexcept {
        const unsigned long _Count = static_cast<unsigned long>(_Bytes.size());
        unsigned long _Written     = 0;
        return ::WriteFile(_Handle, _Bytes.data(), _Count, &_Written, nullptr) != 0
            ? _Written == _Count : false;
    }

    bool file::_Seek(void* const _Handle, const uint64_t _New_pos) noexcept {
        long _High = static_cast<long>((_New_pos & 0xFFFF'FFFF'0000'0000) >> 32);
        return ::SetFilePointer(
            _Handle, static_cast<long>(_New_pos), &_High, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
    }

    bool file::is_open() const noexcept {
        return _Myhandle != nullptr;
    }

    void file::close() noexcept {
        if (_Myhandle) {
            ::CloseHandle(_Myhandle);
            _Myhandle = nullptr;
        }
    }

    size_t file::read(byte_t* const _Buf, const size_t _Count) noexcept {
        if (!_Myhandle) {
            return false;
        }

        if (_Count == 0) { // nothing to read, do nothing
            return true;
        }

        if (!_Buf) { // invalid buffer
            return false;
        }

        const size_t _Read = _Read_bytes(_Myhandle, _Buf, _Count);
#ifdef _M_X64
        _Myoff            += _Read;
#else // ^^^ _M_X64 ^^^ / vvv _M_IX86 vvv
        _Myoff            += static_cast<uint64_t>(_Read);
#endif // _M_X64
        return _Read;
    }

    bool file::write(const byte_string_view _Bytes) noexcept {
        if (!_Myhandle) {
            return false;
        }

        if (_Bytes.empty()) { // nothing to write, do nothing
            return true;
        }

        if (_Write_bytes(_Myhandle, _Bytes)) {
#ifdef _M_X64
            _Myoff += _Bytes.size();
#else // ^^^ _M_X64 ^^^ / vvv _M_IX86 vvv
            _Myoff += static_cast<uint64_t>(_Bytes.size());
#endif // _M_X64
            return true;
        } else {
            return false;
        }
    }

    bool file::seek(const uint64_t _New_pos) noexcept {
        if (!_Myhandle) {
            return false;
        }

        if (_New_pos >= size()) { // out of bounds
            return false;
        }

        if (_Seek(_Myhandle, _New_pos)) {
            _Myoff = _New_pos;
            return true;
        } else {
            return false;
        }
    }

    bool file::seek_for_append() noexcept {
        if (!_Myhandle) {
            return false;
        }

        const uint64_t _New_pos = size(); // last byte offset + 1, allows append
        if (_Seek(_Myhandle, _New_pos)) {
            _Myoff = _New_pos;
            return true;
        } else {
            return false;
        }
    }

    bool file::move(const uint64_t _Off, const move_direction _Direction) noexcept {
        if (!_Myhandle) {
            return false;
        }

        if (_Off == 0) { // no movement, do nothing
            return false;
        }

        if (_Direction == move_direction::backward) { // try move backward
            if (_Off > _Myoff) { // out of bounds
                return false;
            }

            return seek(_Myoff - _Off);
        } else { // try move forward
            if (_Myoff + _Off >= size()) { // out of bounds
                return false;
            }

            return seek(_Myoff + _Off);
        }
    }

    const uint64_t file::tell() const noexcept {
        return _Myoff;
    }

    uint64_t file::size() const noexcept {
        if (!_Myhandle) {
            return 0;
        }

        unsigned long _High = 0;
        return static_cast<uint64_t>(
            ::GetFileSize(_Myhandle, &_High) | (static_cast<uint64_t>(_High) << 32));
    }

    bool file::resize(const uint64_t _New_size) noexcept {
        if (!_Myhandle) {
            return false;
        }

        const uint64_t _Old_size = size();
        if (_New_size == _Old_size) { // nothing will change, do nothing
            return true;
        } else if (_New_size < _Old_size) { // try to decrease the file size
            if (!seek(_New_size)) {
                return false;
            }
        } else { // try to increase the file size
            if (_Seek(_Myhandle, _New_size)) {
                _Myoff = _New_size;
            } else {
                return false;
            }
        }

        return ::SetEndOfFile(_Myhandle) != 0;
    }
} // namespace fcrypt