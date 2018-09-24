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

#ifndef XTT_UTIL_WRAP_KEYS_H
#define XTT_UTIL_WRAP_KEYS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wraps keys from files as ASN.1 and writes to asn1_filename.
 *
 * Returns:
 *      0                       on success
 *      SAVE_TO_FILE_ERROR      an error occurred writing to a file
 *      READ_FROM_FILE_ERROR    an error occurred reading from a file
 *      KEY_CREATION_ERROR      an error occurred creating a keypair
 *      ASN1_CREATION_ERROR     an error occurred creating the wrapped pair
*/

int xtt_wrap_keys_asn1(const char *privkey_filename, const char *pubkey_filename, const char *asn1_filename);

#ifdef __cplusplus
}
#endif

#endif
