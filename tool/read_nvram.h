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

#ifndef XTT_TOOL_READ_NVRAM_H
#define XTT_TOOL_READ_NVRAM_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <xtt/tpm/nvram.h>


int read_nvram(const char* tcti_str, const char* devfile, const char* tpmhostname,
               const char* tpmport, const char* outfile, enum xtt_object_name obj_name);



#ifdef __cplusplus
}
#endif

#endif
