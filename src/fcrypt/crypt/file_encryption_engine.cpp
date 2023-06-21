// file_encryption_engine.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/crypt/file_encryption_engine.hpp>
#include <cstdint>
#include <cstring>

namespace fcrypt {
    metadata::metadata() noexcept : _Myeeid(encryption_engine::none), _Myiv(), _Mytag(), _Mysalt() {}

    metadata::~metadata() noexcept {}

    encryption_engine::id& metadata::get_encryption_engine_id() noexcept {
        return _Myeeid;
    }

    iv& metadata::get_iv() noexcept {
        return _Myiv;
    }

    authentication_tag& metadata::get_tag() noexcept {
        return _Mytag;
    }

    salt& metadata::get_salt() noexcept {
        return _Mysalt;
    }

    void metadata::generate() noexcept {
        _Myiv   = iv::generate();
        _Mysalt = salt::generate();
    }

    bool metadata::extract(file& _File) noexcept {
        const uint64_t _Size = _File.size();
        if (_Size < size) { // the file cannot be smaller than the total metadata size
            return false;
        }

#ifdef _M_X64
        if (!_File.seek(_Size - size)) {
#else // ^^^ _M_X64 ^^^ / vvv _M_IX86 vvv
        if (!_File.seek(_Size - static_cast<uint64_t>(size))) {
#endif // _M_X64
            return false;
        }

        byte_t _Bytes[size] = {0}; // read once as a contiguous array of bytes
        if (_File.read(_Bytes, size) != size) { // incomplete metadata
            return false;
        }

        _Myeeid = static_cast<encryption_engine::id>(_Bytes[0]);
        ::memcpy(_Myiv.get(), _Bytes + _Iv_offset, iv::size);
        ::memcpy(_Mytag.get(), _Bytes + _Tag_offset, authentication_tag::size);
        ::memcpy(_Mysalt.get(), _Bytes + _Salt_offset, salt::size);
        return _File.resize(_Size - size);
    }

    bool metadata::save(file& _File) noexcept {
        if (!_File.seek_for_append()) {
            return false;
        }

        byte_t _Bytes[size] = {0}; // write once as a contiguous array of bytes
        _Bytes[0]           = static_cast<byte_t>(_Myeeid);
        ::memcpy(_Bytes + _Iv_offset, _Myiv.get(), iv::size);
        ::memcpy(_Bytes + _Tag_offset, _Mytag.get(), authentication_tag::size);
        ::memcpy(_Bytes + _Salt_offset, _Mysalt.get(), salt::size);
        return _File.write(byte_string_view{_Bytes, size});
    }

    file_encryption_engine::file_encryption_engine(file& _File, encryption_engine* const _Engine) noexcept
        : _Myiter(_File), _Myeng(_Engine) {}

    file_encryption_engine::~file_encryption_engine() noexcept {}

    bool file_encryption_engine::encrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept {
        if (!_Myeng->setup_encryption(_Key, _Iv)) {
            return false;
        }

        file& _File = _Myiter.source();
        page _Page;
        page_encryption_manager _Mgr(_Myeng);
        _Myiter.reset(); // start from the begin
        while (_Myiter.next()) {
            _Page = _Myiter.current_page();
            if (!_Mgr.encrypt(_Page)) {
                return false;
            }

            _Myiter.move_back(); // move back to overwrite the current page
            if (!_File.write(byte_string_view{_Page.data(), _Page.usage()})) {
                return false;
            }
        }

        return _Myeng->complete_encryption(_Tag);
    }

    bool file_encryption_engine::decrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept {
        if (!_Myeng->setup_decryption(_Key, _Iv)) {
            return false;
        }

        file& _File = _Myiter.source();
        page _Page;
        page_encryption_manager _Mgr(_Myeng);
        _Myiter.reset(); // start from the begin
        while (_Myiter.next()) {
            _Page = _Myiter.current_page();
            if (!_Mgr.decrypt(_Page)) {
                return false;
            }

            _Myiter.move_back(); // move back to overwrite the current page
            if (!_File.write(byte_string_view{_Page.data(), _Page.usage()})) {
                return false;
            }
        }

        return _Myeng->complete_decryption(_Tag);
    }
} // namespace fcrypt