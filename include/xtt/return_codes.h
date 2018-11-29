/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#ifndef XTT_RETURN_CODES_H
#define XTT_RETURN_CODES_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef enum xtt_return_code_type {
    XTT_RETURN_SUCCESS = 0,

    // Next-state codes:
    XTT_RETURN_WANT_WRITE = 1,
    XTT_RETURN_WANT_READ = 2,
    XTT_RETURN_WANT_BUILDSERVERATTEST = 3,
    XTT_RETURN_WANT_PREPARSESERVERATTEST = 4,
    XTT_RETURN_WANT_BUILDIDCLIENTATTEST = 5,
    XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST = 6,
    XTT_RETURN_WANT_VERIFYGROUPSIGNATURE = 7,
    XTT_RETURN_WANT_BUILDIDSERVERFINISHED = 8,
    XTT_RETURN_WANT_PARSEIDSERVERFINISHED = 9,
    XTT_RETURN_HANDSHAKE_FINISHED = 10,

    // Error codes:
    XTT_RETURN_RECEIVED_ERROR_MSG = 11,

    XTT_RETURN_BAD_INIT = 12,
    XTT_RETURN_BAD_IO = 13,
    XTT_RETURN_BAD_HANDSHAKE_ORDER = 14,
    XTT_RETURN_INSUFFICIENT_ENTROPY = 15,
    XTT_RETURN_BAD_IO_LENGTH = 16,
    XTT_RETURN_UINT16_OVERFLOW = 17,
    XTT_RETURN_UINT32_OVERFLOW = 18,
    XTT_RETURN_NULL_BUFFER = 19,
    XTT_RETURN_INCORRECT_TYPE = 20,
    XTT_RETURN_DIFFIE_HELLMAN = 21,
    XTT_RETURN_UNKNOWN_VERSION = 22,
    XTT_RETURN_UNKNOWN_SUITE_SPEC = 23,
    XTT_RETURN_INCORRECT_LENGTH = 24,
    XTT_RETURN_BAD_CLIENT_SIGNATURE = 25,
    XTT_RETURN_BAD_SERVER_SIGNATURE = 26,
    XTT_RETURN_BAD_ROOT_SIGNATURE = 27,
    XTT_RETURN_UNKNOWN_CRYPTO_SPEC = 28,
    XTT_RETURN_BAD_CERTIFICATE = 29,
    XTT_RETURN_UNKNOWN_CERTIFICATE = 30,
    XTT_RETURN_UNKNOWN_GID = 31,
    XTT_RETURN_BAD_GPK = 32,
    XTT_RETURN_BAD_ID = 33,

    // 34 is unused

    XTT_RETURN_CRYPTO = 35,
    XTT_RETURN_DAA = 36,
    XTT_RETURN_BAD_COOKIE = 37,
    XTT_RETURN_COOKIE_ROTATION = 38,
    XTT_RETURN_RECORD_FAILED_CRYPTO = 39,
    XTT_RETURN_BAD_FINISH = 40,
    XTT_RETURN_CONTEXT_BUFFER_OVERFLOW = 41,
} xtt_return_code_type;

const char* xtt_strerror(xtt_return_code_type rc);

#ifdef __cplusplus
}
#endif

#endif

