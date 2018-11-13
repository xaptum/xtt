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

#ifndef XTT_UTIL_GEN_SERVER_CERT_H
#define XTT_UTIL_GEN_SERVER_CERT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generates a server certificate from root_cert_file and root_privatekey_file.
 *
 * Returns:
 *      0                           on success
 *      SAVE_TO_FILE_ERROR          an error occurred writing to a file
 *      READ_FROM_FILE_ERROR        an error occurred reading from a file
 *      KEY_CREATION_ERROR          an error occurred creating a keypair
 *      CERT_CREATION_ERROR         an error occurred creating the certificate
 *      EXPIRY_PASSED               expiry has already passed
*/
int xtt_generate_server_certificate(const char* root_cert_file, const char* root_privatekey_file,
                                    const char* server_privatekey_file, const char* server_publickey_file,
                                    const char* server_id_file, const char* expiry_in,
                                    const char* server_certificate_filename);

#ifdef __cplusplus
}
#endif

#endif
