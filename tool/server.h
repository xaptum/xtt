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

#ifndef XTT_TOOL_SERVER_H
#define XTT_TOOL_SERVER_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "parse_cli.h"

struct xtt_server_certificate_context;
struct xtt_server_cookie_context;

int run_server(struct cli_params* params);

#ifdef __cplusplus
}
#endif

#endif
