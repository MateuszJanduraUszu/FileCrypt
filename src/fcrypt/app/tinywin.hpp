// tinywin.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _FCRYPT_APP_TINYWIN_HPP_
#define _FCRYPT_APP_TINYWIN_HPP_

// Note: These macros exclude unnecessary headers from <Windows.h>.
#define NOIME
#define NOMCX
#define NOSERVICE
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#endif // _FCRYPT_APP_TINYWIN_HPP_