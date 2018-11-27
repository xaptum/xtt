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
#include <stdlib.h>
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
                printf(usage_str, argv[0], argv[1]);
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
                printf(usage_str, argv[0], argv[1]);
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
                printf(usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_genroot_cli(int argc, char **argv, struct cli_params *params)
{
    params->pubkey = "root_pub.bin";
    params->id = NULL;
    params->rootcert = "root_cert.bin";
    const char *usage_str = "Generate a root certificate.\n\n"
        "Usage: %s %s [-h] [-b <file>] [-d <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                      Display this message.\n"
        "\t\t-b --rpub                      Root's public key input location [default = root_pub.bin]\n"
        "\t\t-d --rid                       Root's ID input location [default generates a random ID]\n"
        "\t\t-c --rcert                     Root's certificate key output location [default = root_cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"rpub", required_argument, NULL, 'b'},
        {"rid", required_argument, NULL, 'd'},
        {"rcert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "b:d:c:h", cli_options, NULL)) != -1) {
        switch (c) {
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
                printf(usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}


static
void parse_genservercert_cli(int argc, char **argv, struct cli_params *params)
{
    params->rootcert = "root_cert.bin";
    params->rootpriv = "root_priv.bin";
    params->servercert = "server_cert.bin";
    params->serverpriv = "server_priv.bin";
    params->serverpub = "server_pub.bin";
    params->certreserved = NULL;
    const char *usage_str = "Generate server's certificate.\n\n"
        "Usage: %s %s [-h] [-r <file>] [-p <file>] [-v <file>] [-b <file>] [-x <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-r --rcert                   Root certificate input location [default = root_cert.bin]\n"
        "\t\t-p --rpriv                   Root private key input location [default = root_priv.bin]\n"
        "\t\t-v --serverpriv              Server private key input location [default = server_priv.bin]\n"
        "\t\t-b --serverpub               Server public key input location [default = server_pub.bin]\n"
        "\t\t-x --reserved                Certificate reserved field input location [default = use \"58415054554d534552564552303030313939393931323331\" for reserved field]\n"
        "\t\t-c --out-servercert          Server certificate output location [default = server_cert.bin]\n"        ;

    static struct option cli_options[] =
    {
        {"rcert", required_argument, NULL, 'r'},
        {"rpriv", required_argument, NULL, 'p'},
        {"serverpriv", required_argument, NULL, 'v'},
        {"serverpub", required_argument, NULL, 'b'},
        {"reserved", required_argument, NULL, 'x'},
        {"out-servercert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "r:p:v:b:x:c:h", cli_options, NULL)) != -1) {
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
            case 'c':
                params->servercert = optarg;
                break;
            case 'x':
                params->certreserved = optarg;
                break;
            case 'h':
                printf(usage_str, argv[0], argv[1]);
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
                printf(usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}

static
void parse_runserver_cli(int argc, char** argv, struct cli_params *params){
    params->port=4444;
    params->servercert = "server_cert.bin";
    params->basename = "basename.bin";
    params->privkey = "server_priv.bin";
    params->daagpk = "daa_gpk.bin";

    const char *usage_str = "Run XTT server.\n\n"
        "Usage: %s %s [-h] [-p ####] [-d <file>] [-v <file>] [-b <file>][-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-p --port                    Specifies which port to start the server on [default port: 4444]\n"
        "\t\t-d --daagpk                  Specifies where DAA GPK can be found [default = daa_gpk.bin]\n"
        "\t\t-v --privkey                 Specifies where server private key can be found [default = server_priv.bin]\n"
        "\t\t-b --basename                Specifies where the basename can be found [default = basename.bin]\n"
        "\t\t-c --servercert              Specifies where server certificate can be found [default = server_cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"port", required_argument, NULL, 'p'},
        {"daagpk", required_argument, NULL, 'd'},
        {"privkey", required_argument, NULL, 'v'},
        {"basename", required_argument, NULL, 'b'},
        {"servercert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:d:v:b:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                params->port = atoi(optarg);
                break;
            case 'd':
                params->daagpk = optarg;
                break;
            case 'v':
                params->privkey = optarg;
                break;
            case 'b':
                params->basename = optarg;
                break;
            case 'c':
                params->servercert = optarg;
                break;
            case 'h':
                printf(usage_str, argv[0], argv[1]);
                exit(1);
        }
    }
}

static
void parse_runclient_cli(int argc, char** argv, struct cli_params *params){
    params->portstr = "4444";
    params->serverhost = "127.0.0.1";
    params->longtermcert = "longterm_cert.bin";
    params->longtermpriv = "longterm_priv.bin";
    params->assignedid = "client_id.txt";
    params->basename = "basename.bin";
    params->rootcert = "root_cert.bin";
    params->daagpk = "daa_gpk.bin";
    params->daacred = "daa_cred.bin";
    params->daasecretkey = "daa_secretkey.bin";
    params->usetpm = 0;
    params->suitespec = "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512";
    params->tcti = "device";
    const char *usage_str = "Run XTT client.\n\n"
        "Usage: %s %s [-h] [-p <file>] [-s option] [-a <file>] [-q <file>] [-r <file>] [-d <file>] [-c <file>] [-k <file>]"
        "[-e <file>] [-n <file>] [-m <file>] [-t <file>] [-f <file>] [-i <file>] [b <file>][-v <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-p --port                    Port to connect to [default port: 4444]\n"
        "\t\t-s --suitespec               Suite Spec:\n"
        "\t\t\tX25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512 [default]\n"
        "\t\t\tX25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B\n"
        "\t\t\tX25519_LRSW_ECDSAP256_AES256GCM_SHA512\n"
        "\t\t\tX25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B\n"
        "\t\t-a --serverhost              Specifies what host server to connect to [default = 127.0.0.1]\n"
        "\t\t-q --requestid               Requested client ID [default = NULL identity type]\n"
        "\t\t-d --daagpk                  DAA GPK input location [default = daa_gpk.bin]\n"
        "\t\t-c --daacred                 DAA Credential input location [default = daa_cred.bin]\n"
        "\t\t-k --daasecret               DAA Secret Key input location [default = daa_secretkey.bin]\n"
        "\t\t-e --rcert                   Root Certificate input location [default = root_cert.bin]\n"
        "\t\t-n --basename                Basename input location [default = basename.bin]\n"
        "\t\t-m --tpmuse                  Indicates to use TPM\n"
        "\t\t-t --tctitype                Which TCTI socket is used ('device' or 'socket') [default = device]\n"
        "\t\t-f --devfile                 Device file input location if tcti == device\n"
        "\t\t-i --assignedid              Assigned ID output location [default = client_id.txt]\n"
        "\t\t-b --longtermpub             Longterm Public Key output location [default = longterm_cert.bin]\n"
        "\t\t-v --longtermpriv            Longterm Private Key output location [default = longterm_priv.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"port", required_argument, NULL, 'p'},
        {"suitespec", required_argument, NULL, 's'},
        {"serverhost", required_argument, NULL, 'a'},
        {"requestid", required_argument, NULL, 'q'},
        {"daagpk", required_argument, NULL, 'd'},
        {"daacred", required_argument, NULL, 'c'},
        {"daasecret", required_argument, NULL, 'k'},
        {"rcert", required_argument, NULL, 'e'},
        {"basename", required_argument, NULL, 'n'},
        {"tpmuse", no_argument, NULL, 'm'},
        {"tctitype", required_argument, NULL, 't'},
        {"devfile", required_argument, NULL, 'f'},
        {"assignedid", required_argument, NULL, 'i'},
        {"longtermpub", required_argument, NULL, 'b'},
        {"longtermpriv", required_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},

        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:s:a:q:d:c:k:e:n:mt:f:i:b:v:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                params->portstr = optarg;
                break;
            case 's':
                params->suitespec = optarg;
                break;
            case 'a':
            {
                params->serverhost = optarg;
                break;
            }
            case 'q':
            {
                params->requestid = optarg;
                break;
            }
            case 'd':
            {
                params->daagpk = optarg;
                break;
            }
            case 'c':
            {
                params->daacred = optarg;
                break;
            }
            case 'k':
            {
                params->daasecretkey = optarg;
                break;
            }
            case 'e':
            {
                params->rootcert = optarg;
                break;
            }
            case 'n':
            {
                params->basename = optarg;
                break;
            }
            case 'm':
                params->usetpm = 1;
                break;
            case 't':
                params->tcti = optarg;
                break;
            case 'f':
            {
                params->devfile = optarg;
                break;
            }
            case 'i':
            {
                params->assignedid = optarg;
                break;
            }
            case 'b':
            {
                params->longtermcert = optarg;
                break;
            }
            case 'v':
            {
                params->longtermpriv = optarg;
                break;
            }
            case 'h':
            printf(usage_str, argv[0], argv[1]);
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
        "\trunserver                Run a XTT server.\n"
        "\trunclient                Run a XTT client.\n"
        "\tinfocert                 Get information about a certificate.\n"
        ;

    if(argc <=1 || strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        printf(usage_str, argv[0]);
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
    } else if (strcmp(argv[1], "runserver")==0)
    {
        params->command=action_runserver;
        parse_runserver_cli(argc, argv, params);
    } else if (strcmp(argv[1], "runclient")==0)
    {
        params->command=action_runclient;
        parse_runclient_cli(argc, argv, params);
    } else if (strcmp(argv[1], "infocert")==0)
    {
        params->command=action_infocert;
        parse_infocert_cli(argc, argv, params);
    } else
    {
        fprintf(stderr, "'%s' is not an option for the XTT tool.\n", argv[1]);
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }
}
