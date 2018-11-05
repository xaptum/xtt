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

#include <xtt/tpm/handles.h>

uint32_t xtt_key_handle(void)
{
    return XTT_KEY_HANDLE;
}

uint32_t xtt_gpk_handle(void)
{
    return XTT_GPK_HANDLE;
}

uint32_t xtt_cred_handle(void)
{
    return XTT_CRED_HANDLE;
}

uint32_t xtt_root_id_handle(void)
{
    return XTT_ROOT_ID_HANDLE;
}

uint32_t xtt_root_pubkey_handle(void)
{
    return XTT_ROOT_PUBKEY_HANDLE;
}

uint32_t xtt_basename_size_handle(void)
{
    return XTT_BASENAME_SIZE_HANDLE;
}

uint32_t xtt_basename_handle(void)
{
    return XTT_BASENAME_HANDLE;
}

uint32_t xtt_server_id_handle(void)
{
    return XTT_SERVER_ID_HANDLE;
}
