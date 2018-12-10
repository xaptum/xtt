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
 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>
 #include <assert.h>

 #include <xtt/util/util_errors.h>
 #include <xtt/tpm/context.h>

 const char *tpm_hostname_g = "localhost";
 const char *tpm_port_g = "2321";

 int initialize_tcti(TSS2_TCTI_CONTEXT **tcti_context, xtt_tcti_type tcti_type, const char *dev_file)
 {
     static unsigned char tcti_context_buffer_s[256];
     *tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_s;
     switch (tcti_type) {
         case XTT_TCTI_SOCKET:
             assert(tss2_tcti_getsize_socket() < sizeof(tcti_context_buffer_s));
             if (TSS2_RC_SUCCESS != tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, *tcti_context)) {
                 fprintf(stderr, "Error: Unable to initialize socket TCTI context\n");
                 return TPM_ERROR;
             }
             break;
         case XTT_TCTI_DEVICE:
             assert(tss2_tcti_getsize_device() < sizeof(tcti_context_buffer_s));
             if (TSS2_RC_SUCCESS != tss2_tcti_init_device(dev_file, strlen(dev_file), *tcti_context)) {
                 fprintf(stderr, "Error: Unable to initialize device TCTI context\n");
                 return TPM_ERROR;
             }
             break;
     }

     return 0;
 }

 int initialize_sapi(TSS2_SYS_CONTEXT *sapi_context,
                      size_t sapi_ctx_size,
                      TSS2_TCTI_CONTEXT *tcti_context)
 {
     TSS2_RC ret = TSS2_RC_SUCCESS;

     if (NULL == sapi_context) {
         fprintf(stderr, "Error allocating memory for TPM SAPI context\n");
         return TPM_ERROR;
     }

     TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
     ret = Tss2_Sys_Initialize(sapi_context,
                               sapi_ctx_size,
                               tcti_context,
                               &abi_version);
     if (TSS2_RC_SUCCESS != ret) {
         fprintf(stderr, "Error initializing TPM SAPI context\n");
         goto finish;
     }

 finish:
     Tss2_Sys_Finalize(sapi_context);

     if (ret == TSS2_RC_SUCCESS) {
         return 0;
     } else {
         return TPM_ERROR;
     }
 }
