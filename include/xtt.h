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

#ifndef XTT_H
#define XTT_H
#pragma once

#include <xtt/certificates.h>
#include <xtt/context.h>
#include <xtt/crypto.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/daa_wrapper.h>
#include <xtt/return_codes.h>
#include <xtt/messages.h>
#include <xtt/util/asn1.h>
#include <xtt/util/generate_x509_certificate.h>
#include <xtt/util/root.h>
#include <xtt/util/generate_server_certificate.h>
#include <xtt/util/file_io.h>
#include <xtt/util/util_errors.h>

#ifdef USE_TPM
#include <xtt/tpm/context.h>
#endif

#endif
