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
#include <xtt/tpm/nvram.h>

typedef enum {
    action_genkey,
    action_genx509cert,
    action_wrapkeys,
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
    const char* privkey;
    const char* pubkey;
    const char* id;
    const char* cert;
    const char* asn1;
    const char* certreserved;
    const char* rootcert;
    const char* rootpriv;
    const char* serverpriv;
    const char* serverpub;
    const char* servercert;
    const char* basename;
    const char* daagpk;
    const char* portstr;
    unsigned short port;
    bool usetpm;
    const char* tcti;
    const char* suitespec;
    const char* serverhost;
    const char* devfile;
    const char* daacred;
    const char* daasecretkey;
    const char* requestid;
    const char* longtermcert;
    const char* longtermpriv;
    const char* assignedid;
    const char* tpmhostname;
    const char* tpmport;
    const char* outfile;
    enum xtt_object_name obj_name;

};

void parse_cli(int argc, char **argv, struct cli_params *params);

#ifdef __cplusplus
}
#endif

#endif
