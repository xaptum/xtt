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

#ifndef XTT_BYTE_UTILS_INTERNAL_H
#define XTT_BYTE_UTILS_INTERNAL_H
#pragma once

#include <xtt/context.h>
#include <xtt/crypto_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void short_to_bigendian(uint16_t in,
                        unsigned char out[2]);

void bigendian_to_short(const unsigned char in[2],
                        uint16_t* out);

void long_to_bigendian(uint32_t in,
                       unsigned char out[4]);

void bigendian_to_long(const unsigned char in[4],
                       uint32_t* out);

void longlong_to_bigendian(uint64_t in,
                           unsigned char out[8]);

void bigendian_to_longlong(const unsigned char in[8],
                           uint64_t* out);

void xor_equals(unsigned char* left,
                const unsigned char* right,
                uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
