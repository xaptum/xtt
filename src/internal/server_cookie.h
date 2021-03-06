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

#ifndef XTT_INTERNAL_SERVER_COOKIE_H
#define XTT_INTERNAL_SERVER_COOKIE_H
#pragma once

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>

#ifdef __cplusplus
extern "C" {
#endif

xtt_return_code_type
build_server_cookie(xtt_server_cookie *cookie,
                    struct xtt_handshake_context *handshake_ctx,
                    struct xtt_server_cookie_context *cookie_ctx);

xtt_return_code_type
validate_server_cookie(xtt_server_cookie *cookie,
                       struct xtt_handshake_context *handshake_ctx,
                       struct xtt_server_cookie_context *cookie_ctx);

#ifdef __cplusplus
}
#endif

#endif

