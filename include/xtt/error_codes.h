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

#ifndef XTT_ERROR_CODES_H
#define XTT_ERROR_CODES_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef enum xtt_error_code {
    XTT_ERROR_SUCCESS = 0,
    XTT_ERROR_BAD_INIT,
    XTT_ERROR_INSUFFICIENT_ENTROPY,
    XTT_ERROR_UINT32_OVERFLOW,
    XTT_ERROR_NULL_BUFFER,
    XTT_ERROR_INCORRECT_TYPE,
    XTT_ERROR_DIFFIE_HELLMAN,
    XTT_ERROR_UNKNOWN_VERSION,
    XTT_ERROR_UNKNOWN_SUITE_SPEC,
    XTT_ERROR_INCORRECT_LENGTH,
    XTT_ERROR_BAD_SIGNATURE,
    XTT_ERROR_UNKNOWN_CRYPTO_SPEC,
    XTT_ERROR_BAD_CERTIFICATE,
    XTT_ERROR_BAD_EXPIRY,
    XTT_ERROR_CRYPTO,
    XTT_ERROR_DAA,
    XTT_ERROR_BAD_COOKIE,
    XTT_ERROR_COOKIE_ROTATION,
    XTT_ERROR_WANT_READ,
    XTT_ERROR_RECORD_FAILED_CRYPTO,
    XTT_ERROR_BAD_FINISH,
    XTT_ERROR_CONTEXT_BUFFER_OVERFLOW
} xtt_error_code;

void xtt_strerror(xtt_error_code errnum, char* buffer, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif

