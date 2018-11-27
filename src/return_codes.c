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

#include <xtt/return_codes.h>

static const char* strerr_arr[] =
{
    "XTT - SUCCESS",

    "XTT - WANT_WRITE",
    "XTT - WANT_READ",
    "XTT - WANT_BUILDSERVERATTEST",
    "XTT - WANT_PREPARSESERVERATTEST",
    "XTT - WANT_BUILDIDCLIENTATTEST",
    "XTT - WANT_PREPARSEIDCLIENTATTEST",
    "XTT - WANT_VERIFYGROUPSIGNATURE",
    "XTT - WANT_BUILDIDSERVERFINISHED",
    "XTT - WANT_PARSEIDSERVERFINISHED",
    "XTT - HANDSHAKE_FINISHED",

    "XTT - RECEIVED_ERROR_MSG",

    "XTT - BAD_INIT",
    "XTT - BAD_IO",
    "XTT - BAD_HANDSHAKE_ORDER",
    "XTT - INSUFFICIENT_ENTROPY",
    "XTT - BAD_IO_LENGTH",
    "XTT - UINT16_OVERFLOW",
    "XTT - UINT32_OVERFLOW",
    "XTT - NULL_BUFFER",
    "XTT - INCORRECT_TYPE",
    "XTT - DIFFIE_HELLMAN",
    "XTT - UNKNOWN_VERSION",
    "XTT - UNKNOWN_SUITE_SPEC",
    "XTT - INCORRECT_LENGTH",
    "XTT - BAD_CLIENT_SIGNATURE",
    "XTT - BAD_SERVER_SIGNATURE",
    "XTT - BAD_ROOT_SIGNATURE",
    "XTT - UNKNOWN_CRYPTO_SPEC",
    "XTT - BAD_CERTIFICATE",
    "XTT - UNKNOWN_CERTIFICATE",
    "XTT - UNKNOWN_GID",
    "XTT - BAD_GPK",
    "XTT - BAD_ID",
    "XTT - UNUSED_1",
    "XTT - CRYPTO",
    "XTT - DAA",
    "XTT - BAD_COOKIE",
    "XTT - COOKIE_ROTATION",
    "XTT - RECORD_FAILED_CRYPTO",
    "XTT - BAD_FINISH",
    "XTT - CONTEXT_BUFFER_OVERFLOW",
};

const char* xtt_strerror(xtt_return_code_type rc)
{
    static const size_t max_rc = (sizeof(strerr_arr) / sizeof(char*)) - 1;
    if (rc > max_rc) {
        return "XTT - Unknown return code";
    } else {
        return strerr_arr[rc];
    }
}
