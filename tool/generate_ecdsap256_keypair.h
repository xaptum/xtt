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

#ifndef XTT_TOOL_GEN_KEYPAIR_H
#define XTT_TOOL_GEN_KEYPAIR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generates a ECDSA keypair and saves the key pair to keypair_file
 *
 * Returns:
 *      0   on success
 *      SAVE_TO_FILE_ERROR   an error occurred writing to a file
 *      KEY_CREATION_ERROR   an error occurred creating the keypair
*/
int xtt_generate_ecdsap256_keypair(const char *keypair_file);

#ifdef __cplusplus
}
#endif

#endif
