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

#include "byte_utils.h"

#include <assert.h>

/* TODO: Create versions optimized for Linux on x64 */
/* And, if already big-endian, noop */

void short_to_bigendian(uint16_t in,
                        unsigned char out[2])
{
    out[0] = (unsigned char)(in >> 8);   /* 1*8 */
    out[1] = (unsigned char)(in);        /* 0*8 */
}

void bigendian_to_short(const unsigned char in[2],
                        uint16_t* out)
{
    *out = (uint64_t)(in[1]);
    *out |= (uint64_t)(in[0]) << 8;
}

void long_to_bigendian(uint32_t in,
                       unsigned char out[4])
{
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
}

void bigendian_to_long(const unsigned char in[4],
                       uint32_t* out)
{
    *out = (uint64_t)(in[3]);
    *out |= (uint64_t)(in[2]) << 8;
    *out |= (uint64_t)(in[1]) << 16;
    *out |= (uint64_t)(in[0]) << 24;
}

void longlong_to_bigendian(uint64_t in,
                           unsigned char out[8])
{
    out[0] = (unsigned char)(in >> 56);  /* 7*8 */
    out[1] = (unsigned char)(in >> 48);  /* 6*8 */
    out[2] = (unsigned char)(in >> 40);  /* 5*8 */
    out[3] = (unsigned char)(in >> 32);  /* 4*8 */
    out[4] = (unsigned char)(in >> 24);  /* 3*8 */
    out[5] = (unsigned char)(in >> 16);  /* 2*8 */
    out[6] = (unsigned char)(in >> 8);   /* 1*8 */
    out[7] = (unsigned char)(in);        /* 0*8 */
}

void bigendian_to_longlong(const unsigned char in[8],
                           uint64_t* out)
{
    *out = (uint64_t)(in[7]);
    *out |= (uint64_t)(in[6]) << 8;
    *out |= (uint64_t)(in[5]) << 16;
    *out |= (uint64_t)(in[4]) << 24;
    *out |= (uint64_t)(in[3]) << 32;
    *out |= (uint64_t)(in[2]) << 40;
    *out |= (uint64_t)(in[1]) << 48;
    *out |= (uint64_t)(in[0]) << 56;
}

void xor_equals(unsigned char* left,
                const unsigned char* right,
                uint32_t length)
{
    uint32_t i = 0;
    for (; i < length; ++i)
        left[i] = left[i] ^ right[i];
}
