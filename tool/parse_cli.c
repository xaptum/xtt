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

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include "parse_cli.h"

static
void parse_genkey_cli(int argc, char **argv, struct cli_params *params)
{
    params->pubkey = "pub.bin";
    params->privkey = "priv.bin";
    const char *usage_str = "Generate ECDSA keys for XTT.\n\n"
        "Usage: %s %s [-h] [-v <file>] [-b <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help             Display this message.\n"
        "\t\t-v --privkey          Private key output location [default = priv.bin]\n"
        "\t\t-b --pubkey           Public key output location [default = pub.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"privkey", required_argument, NULL, 'v'},
        {"pubkey", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "v:b:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                params->privkey=optarg;
                break;
            case 'b':
                params->pubkey=optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_genx509cert_cli(int argc, char **argv, struct cli_params *params)
{
    params->cert = "cert.bin";
    params->id = "id.bin";
    params->privkey = "priv.bin";
    params->pubkey = "pub.bin";

    const char *usage_str = "Generate x509 certificate.\n\n"
        "Usage: %s %s [-h] [-v <file>] [-b <file>] [-d <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help             Display this message.\n"
        "\t\t-v --privkey          Private key input location [default = priv.bin]\n"
        "\t\t-b --pubkey           Public key input location [default = pub.bin]\n"
        "\t\t-d --id               ID input location [default = id.bin]\n"
        "\t\t-c --certificate      Certificate output location [default = cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"privkey", required_argument, NULL, 'v'},
        {"pubkey", required_argument, NULL, 'b'},
        {"id", required_argument, NULL, 'd'},
        {"certificate", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "v:b:d:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                params->privkey = optarg;
                break;
            case 'b':
                params->pubkey = optarg;
                break;
            case 'd':
                params->id = optarg;
                break;
            case 'c':
                params->cert = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_wrapkeys_cli(int argc, char **argv, struct cli_params *params)
{
    params->privkey = "priv.bin";
    params->pubkey = "pub.bin";
    params->asn1 = "priv.asn1.bin";
    const char *usage_str = "Wrap keys in ASN.1 formatting.\n\n"
        "Usage: %s %s [-h] [-v <file>] [-b <file>] [-a <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-v --priv              Private key input location [default = priv.bin]\n"
        "\t\t-b --pub               Public key input location [default = pub.bin]\n"
        "\t\t-a --out-asn1          ASN.1 output location [default = priv.asn1.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"in-priv", required_argument, NULL, 'v'},
        {"in-pub", required_argument, NULL, 'b'},
        {"out-asn1", required_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "v:b:d:a:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                params->privkey = optarg;
                break;
            case 'b':
                params->pubkey = optarg;
                break;
            case 'a':
                params->asn1 = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_genroot_cli(int argc, char **argv, struct cli_params *params)
{
    params->privkey = "root_priv.bin";
    params->pubkey = "root_pub.bin";
    params->id = NULL;
    params->rootcert = "root_cert.bin";
    const char *usage_str = "Generate a root certificate.\n\n"
        "Usage: %s %s [-h] [-v <file>] [-b <file>] [-d <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                      Display this message.\n"
        "\t\t-v --rpriv                     Root's private key output location [default = root_priv.bin]\n"
        "\t\t-b --rpub                      Root's public key output location [default = root_pub.bin]\n"
        "\t\t-d --rid                       Root's ID input location [default generates a random ID]\n"
        "\t\t-c --rcert                     Root's public key output location [default = root_cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"rpriv", required_argument, NULL, 'v'},
        {"rpub", required_argument, NULL, 'b'},
        {"rid", required_argument, NULL, 'd'},
        {"rcert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "v:b:d:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                params->privkey = optarg;
                break;
            case 'b':
                params->pubkey = optarg;
                break;
            case 'd':
                params->id = optarg;
                break;
            case 'c':
                params->rootcert = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_genservercert_cli(int argc, char **argv, struct cli_params *params)
{
    params->rootcert = "root_cert.bin";
    params->rootpriv = "root_priv.bin";
    params->server_id = "server_id.bin";
    params->servercert = "server_cert.bin";
    params->serverpriv = "server_priv.bin";
    params->serverpub = "server_pub.bin";
    params->time = NULL;
    const char *usage_str = "Generate server's certificate.\n\n"
        "Usage: %s %s [-h] [-r <file>] [-p <file>] [-v <file>] [-b <file>] [-s <file>] [-e 'YYYYMMDD'][-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-r --rcert                   Root certificate input location [default = root_cert.bin]\n"
        "\t\t-p --rpriv                   Root private key input location [default = root_priv.bin]\n"
        "\t\t-v --serverpriv              Server private key input location [default = server_priv.bin]\n"
        "\t\t-b --serverpub               Server private key output location [default = server_pub.bin]\n"
        "\t\t-s --sid                     Server ID input location [default = server_id.bin]\n"
        "\t\t-e --expiry                  Year, month and day when certificate will expire in format YYYYMMDD [default 1 year]\n"
        "\t\t-c --out-servercert          Server certificate output location [default = server_cert.bin]\n"        ;

    static struct option cli_options[] =
    {
        {"rcert", required_argument, NULL, 'r'},
        {"rpriv", required_argument, NULL, 'p'},
        {"serverpriv", required_argument, NULL, 'v'},
        {"serverpub", required_argument, NULL, 'b'},
        {"sid", required_argument, NULL, 's'},
        {"expiry", required_argument, NULL, 'e'},
        {"out-servercert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "r:p:v:b:s:e:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'r':
                params->rootcert = optarg;
                break;
            case 'p':
                params->rootpriv = optarg;
                break;
            case 'v':
                params->serverpriv = optarg;
                break;
            case 'b':
                params->serverpub = optarg;
                break;
            case 's':
                params->server_id = optarg;
                break;
            case 'e':
                params->time = optarg;
                break;
            case 'c':
                params->servercert = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }

}

static
void parse_infocert_cli(int argc, char** argv, struct cli_params *params){
    params->rootcert = NULL;
    params->servercert = NULL;
    const char *usage_str = "Parse certificates and print out important information.\n\n"
        "Usage: %s %s [-h] [-r <file>] [-s <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-r --rootcert          Root certificate to be parsed\n"
        "\t\t-s --servercert        Server certificate to be parsed\n"
        ;

    static struct option cli_options[] =
    {
        {"rootcert", required_argument, NULL, 'r'},
        {"servercert", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "r:s:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'r':
                params->rootcert=optarg;
                break;
            case 's':
                params->servercert=optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


void parse_cli(int argc, char** argv, struct cli_params *params)
{
    const char *usage_str =
        "Usage: %s [command] --command_options\n"
        "Commands:\n"
        "\tgenkey                   Generate ECDSA keys for XTT.\n"
        "\tgenx509cert              Generate x509 certificate.\n"
        "\twrapkeys                 Generate ASN.1 wrapped keys.\n"
        "\tgenrootcert              Generate root certificate.\n"
        "\tgenservercert            Generate server certificate and server private key.\n"
        "\tinfocert                 Get information about a certificate.\n"
        ;

    if(argc <=1 || strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }

    if(strcmp(argv[1], "genkey")==0)
    {
        params->command=action_genkey;
        parse_genkey_cli(argc, argv, params);
    } else if (strcmp(argv[1], "genx509cert")==0)
    {
        params->command=action_genx509cert;
        parse_genx509cert_cli(argc, argv, params);
    }else if (strcmp(argv[1], "wrapkeys")==0)
    {
        params->command=action_wrapkeys;
        parse_wrapkeys_cli(argc, argv, params);
    }else if (strcmp(argv[1], "genrootcert")==0)
    {
        params->command=action_genrootcert;
        parse_genroot_cli(argc, argv, params);
    }else if (strcmp(argv[1], "genservercert")==0)
    {
        params->command=action_genservercert;
        parse_genservercert_cli(argc, argv, params);
    } else if (strcmp(argv[1], "infocert")==0)
    {
        params->command=action_infocert;
        parse_infocert_cli(argc, argv, params);
    } else
    {
        printf("'%s' is not an option for the XTT tool.\n", argv[1]);
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }
}
