// encryption_engine.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcrypt/crypt/encryption_engine.hpp>

namespace fcrypt {
    extern [[nodiscard]] encryption_engine* _Make_aes256_gcm_engine() noexcept;

    encryption_engine::encryption_engine() noexcept {}

    encryption_engine::~encryption_engine() noexcept {}

    [[nodiscard]] encryption_engine* make_encryption_engine(const encryption_engine::id _Id) noexcept {
        switch (_Id) {
        case encryption_engine::aes256_gcm:
            return _Make_aes256_gcm_engine();
        default:
            return nullptr;
        }
    }
} // namespace fcrypt