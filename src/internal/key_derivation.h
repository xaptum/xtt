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

#ifndef XTT_INTERNAL_KEY_DERIVATION_H
#define XTT_INTERNAL_KEY_DERIVATION_H
#pragma once

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/error_codes.h>

#ifdef __cplusplus
extern "C" {
#endif

xtt_error_code
derive_handshake_keys(struct xtt_handshake_context *handshake_ctx,
                      const unsigned char *client_init,
                      const unsigned char *server_initandattest_uptocookie,
                      const xtt_server_cookie *server_cookie,
                      const unsigned char *others_pub_key,
                      int is_client);

#ifdef __cplusplus
}
#endif

#endif

