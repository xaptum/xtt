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

#include <stdint.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

typedef enum {
    action_genkey,
    action_genx509cert,
    action_wrapkeys,
    action_genrootcert,
    action_genservercert,
    action_help
} action;

struct cli_params{
    action command;
    const char* privkey;
    const char* pubkey;
    const char* id;
    const char* cert;
    const char* asn1;
    const char* server_id;
    const char* time;
    const char* rootcert;
    const char* rootpriv;
    const char* servercert;
    const char* serverpriv;
    const char* serverpub;
    const char* basename;
};

void parse_cli(int argc, char **argv, struct cli_params *params);

#ifdef __cplusplus
}
#endif

#endif
