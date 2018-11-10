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

#pragma once

#ifndef XTT_CRYPTO_H
#define XTT_CRYPTO_H

#include "crypto_types.h"
#include "crypto/hmac.h"
#include "crypto/kx.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A generic interface for XTT cipher suite algorithms.
 *
 * A cipher suite specifies algorithms for key exchange, attestation,
 * signing, AEAD, and HMAC.
 *
 * Note: Currently only the key exchange and HMAC algorithms are
 * exposed.
 */
struct xtt_suite_ops {
    struct xtt_crypto_kx_ops   *kx;
    struct xtt_crypto_hmac_ops *hmac;
};


/**
 * Gets the :xtt_suite_ops: for the given suite spec.
 *
 * @suite_spec the suite spec
 * @returns pointer to the suite ops or :NULL: if the suite spec is
 * not found
 */
const struct xtt_suite_ops*
xtt_suite_ops_get(xtt_suite_spec suite_spec);

#ifdef __cplusplus
}
#endif

#endif
