// page.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/fs/page.hpp>
#include <cstddef>
#include <cstring>
#include <type_traits>

namespace fcrypt {
    page::page() noexcept : _Mydata{0}, _Myusage(size) {}

    page::page(const page& _Other) noexcept : _Myusage(_Other._Myusage) {
        _Copy_data(_Other._Mydata);
    }

    page::page(page&& _Other) noexcept : _Myusage(_Other._Myusage) {
        _Move_data(_Other._Mydata);
        _Other._Myusage = 0;
    }

    page::~page() noexcept {
        _Scrub_memory(_Mydata, size);
    }

    page& page::operator=(const page& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            _Copy_data(_Other._Mydata);
            _Myusage = _Other._Myusage;
        }

        return *this;
    }

    page& page::operator=(page&& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            _Move_data(_Other._Mydata);
            _Myusage        = _Other._Myusage;
            _Other._Myusage = 0;
        }

        return *this;
    }

    void page::_Copy_data(const byte_t (&_Data)[size]) noexcept {
        ::memcpy(_Mydata, _Data, size);
    }

    void page::_Move_data(byte_t (&_Data)[size]) noexcept {
        ::memcpy(_Mydata, _Data, size);
        _Scrub_memory(_Data, size);
    }

    const size_t page::usage() const noexcept {
        return _Myusage;
    }

    void page::usage(const size_t _New_usage) noexcept {
        _Myusage = _Min(_New_usage, size); // usage cannot be greater than the total page size
    }

    byte_t* page::data() noexcept {
        return _Mydata;
    }

    const byte_t* page::data() const noexcept {
        return _Mydata;
    }

    page_encryption_manager::page_encryption_manager(encryption_engine* const _Engine) noexcept
        : _Myeng(_Engine) {}

    page_encryption_manager::~page_encryption_manager() noexcept {}

    bool page_encryption_manager::encrypt(page& _Page) noexcept {
        const byte_t* const _Data = _Page.data();
        return _Myeng->encrypt(_Data, _Page.usage(), _Page.data());
    }

    bool page_encryption_manager::decrypt(page& _Page) noexcept {
        const byte_t* const _Data = _Page.data();
        return _Myeng->decrypt(_Data, _Page.usage(), _Page.data());
    }

    page_iterator::page_iterator(file& _File) noexcept : _Myfile(_File), _Mypage() {}

    page_iterator::~page_iterator() noexcept {}

    const page& page_iterator::current_page() const noexcept {
        return _Mypage;
    }

    file& page_iterator::source() noexcept {
        return _Myfile;
    }

    void page_iterator::reset() noexcept {
        _Myfile.seek(0);
        _Mypage = page{};
    }

    bool page_iterator::next() noexcept {
        page _Next_page;
        const size_t _Read = _Myfile.read(_Next_page.data(), page::size);
        if (_Read == 0) { // no more data
            return false;
        }

        if (_Read != page::size) { // trim data
            _Next_page.usage(_Read);
        }

        _Mypage = ::std::move(_Next_page);
        return true;
    }

    void page_iterator::move_back() noexcept {
#ifdef _M_X64
        _Myfile.move(_Mypage.usage(), move_direction::backward);
#else // ^^^ _M_X64 ^^^ / vvv _M_IX86 vvv
        _Myfile.move(static_cast<uint64_t>(_Mypage.usage()), move_direction::backward);
#endif // _M_X64
    }
} // namespace fcrypt