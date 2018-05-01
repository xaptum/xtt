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
    XTT_RETURN_WANT_WRITE,
    XTT_RETURN_WANT_READ,
    XTT_RETURN_WANT_BUILDSERVERATTEST,
    XTT_RETURN_WANT_PREPARSESERVERATTEST,
    XTT_RETURN_WANT_BUILDIDCLIENTATTEST,
    XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST,
    XTT_RETURN_WANT_VERIFYGROUPSIGNATURE,
    XTT_RETURN_WANT_BUILDIDSERVERFINISHED,
    XTT_RETURN_WANT_PARSEIDSERVERFINISHED,
    XTT_RETURN_HANDSHAKE_FINISHED,

    // Error codes:
    XTT_RETURN_RECEIVED_ERROR_MSG,

    XTT_RETURN_BAD_INIT,
    XTT_RETURN_BAD_HANDSHAKE_ORDER,
    XTT_RETURN_INSUFFICIENT_ENTROPY,
    XTT_RETURN_BAD_IO_LENGTH,
    XTT_RETURN_UINT16_OVERFLOW,
    XTT_RETURN_UINT32_OVERFLOW,
    XTT_RETURN_NULL_BUFFER,
    XTT_RETURN_INCORRECT_TYPE,
    XTT_RETURN_DIFFIE_HELLMAN,
    XTT_RETURN_UNKNOWN_VERSION,
    XTT_RETURN_UNKNOWN_SUITE_SPEC,
    XTT_RETURN_INCORRECT_LENGTH,
    XTT_RETURN_BAD_CLIENT_SIGNATURE,
    XTT_RETURN_BAD_SERVER_SIGNATURE,
    XTT_RETURN_BAD_ROOT_SIGNATURE,
    XTT_RETURN_UNKNOWN_CRYPTO_SPEC,
    XTT_RETURN_BAD_CERTIFICATE,
    XTT_RETURN_BAD_EXPIRY,
    XTT_RETURN_CRYPTO,
    XTT_RETURN_DAA,
    XTT_RETURN_BAD_COOKIE,
    XTT_RETURN_COOKIE_ROTATION,
    XTT_RETURN_RECORD_FAILED_CRYPTO,
    XTT_RETURN_BAD_FINISH,
    XTT_RETURN_CONTEXT_BUFFER_OVERFLOW
} xtt_return_code_type;

void xtt_strerror(xtt_return_code_type rc, char* buffer, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif

