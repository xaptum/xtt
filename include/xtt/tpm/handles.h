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

#ifndef XTT_TPM_HANDLES_H
#define XTT_TPM_HANDLES_H
#pragma once

#include <stdint.h>

#define XTT_KEY_HANDLE 0x81800000
uint32_t xtt_key_handle(void);

#define XTT_GPK_HANDLE 0x1410000
uint32_t xtt_gpk_handle(void);

#define XTT_CRED_HANDLE 0x1410001
uint32_t xtt_cred_handle(void);

#define XTT_CRED_SIG_HANDLE 0x1410002
uint32_t xtt_cred_sig_handle(void);

#define XTT_ROOT_ASN1CERT_HANDLE 0x1410005
uint32_t xtt_root_asn1cert_handle(void);

#define XTT_BASENAME_HANDLE 0x1410007
uint32_t xtt_basename_handle(void);

#define XTT_ROOT_XTTCERT_HANDLE 0x1410009
uint32_t xtt_root_xttcert_handle(void);

#endif
