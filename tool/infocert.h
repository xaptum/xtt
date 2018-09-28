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

#ifndef XTT_UTIL_INFO_CERT_H
#define XTT_UTIL_INFO_CERT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum infocert_type {
    infocert_type_server,
    infocert_type_root
};

/*
 * Parses certificate and prints important info to screen
 *
 * Returns:
 * 0                        on success
 * PARSE_CERT_ERROR         if infocert_type is not set
 * READ_FROM_FILE_ERROR     error while reading in file
*/
int info_cert(const char* filename, enum infocert_type type);

#ifdef __cplusplus
}
#endif

#endif
