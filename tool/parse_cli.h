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

#ifndef PARSE_CLI_H
#define PARSE_CLI_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#ifdef USE_TPM
#include <xtt/tpm/context.h>
#include <xaptum-tpm/nvram.h>
#endif

typedef enum {
    action_genkey,
    action_genx509cert,
    action_genrootcert,
    action_genservercert,
    action_runserver,
    action_runclient,
    action_infocert,
    action_readnvram,
    action_help
} action;

struct cli_params {
    action command;
    const char* keypair;
    const char* id;
    const char* cert;
    const char* certreserved;
    const char* rootcert;
    const char* serverkeypair;
    const char* servercert;
    const char* basename;
    const char* daagpk;
    const char* portstr;
    unsigned short port;
    bool usetpm;
    const char* suitespec;
    const char* serverhost;
    const char* daacred;
    const char* daasecretkey;
    const char* requestid;
    const char* longtermcert;
    const char* longtermpriv;
    const char* assignedid;
    const char* outfile;

#ifdef USE_TPM
    const char* tcti_conf;
    enum xtpm_object_name obj_name;
#endif

};

void parse_cli(int argc, char **argv, struct cli_params *params);

#ifdef __cplusplus
}
#endif

#endif
