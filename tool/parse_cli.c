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

#include "parse_cli.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static
void parse_genkey_cli(int argc, char **argv, struct cli_params *params)
{
    params->keypair = "keys.asn1.bin";
    const char *usage_str = "Generate ECDSA keys for XTT.\n\n"
        "Usage: %s %s [-h] [-k <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help             Display this message.\n"
        "\t\t-k --keypair          Key Pair output location [default = keys.asn1.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"keypair", required_argument, NULL, 'k'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "k:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'k':
                params->keypair=optarg;
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
    params->keypair = "keys.asn1.bin";

    const char *usage_str = "Generate x509 certificate.\n\n"
        "Usage: %s %s [-h] [-v <file>] [-b <file>] [-d <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help             Display this message.\n"
        "\t\t-k --keypair          Key pair input location [default = keys.asn1.bin]\n"
        "\t\t-d --id               ID input location [default = id.bin]\n"
        "\t\t-c --certificate      Certificate output location [default = cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"keypair", required_argument, NULL, 'k'},
        {"id", required_argument, NULL, 'd'},
        {"certificate", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "k:d:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'k':
                params->keypair = optarg;
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
void parse_genroot_cli(int argc, char **argv, struct cli_params *params)
{
    params->keypair = "root_keys.asn1.bin";
    params->id = NULL;
    params->rootcert = "root_cert.bin";
    const char *usage_str = "Generate a root certificate.\n\n"
        "Usage: %s %s [-h] [-k <file>] [-d <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                      Display this message.\n"
        "\t\t-k --keypair                   Root's key pair input location [default = root_keys.asn1.bin]\n"
        "\t\t-d --rid                       Root's ID input location [default generates a random ID]\n"
        "\t\t-c --rcert                     Root's certificate key output location [default = root_cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"keypair", required_argument, NULL, 'k'},
        {"rid", required_argument, NULL, 'd'},
        {"rcert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "k:d:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'k':
                params->keypair = optarg;
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
    params->keypair = "root_keys.asn1.bin";
    params->servercert = "server_cert.bin";
    params->serverkeypair = "server_keys.asn1.bin";
    params->certreserved = NULL;
    const char *usage_str = "Generate server's certificate.\n\n"
        "Usage: %s %s [-h] [-r <file>] [-p <file>] [-v <file>] [-b <file>] [-x <file>] [-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-r --rcert                   Root certificate input location [default = root_cert.bin]\n"
        "\t\t-k --rkeypair                Root key pair input location [default = root_keys.asn1.bin]\n"
        "\t\t-s --skeypair                Server key pair input location [default = server_keys.asn1.bin]\n"
        "\t\t-x --reserved                Certificate reserved field input location [default = use \"58415054554d534552564552303030313939393931323331\" for reserved field]\n"
        "\t\t-c --out-servercert          Server certificate output location [default = server_cert.bin]\n"        ;

    static struct option cli_options[] =
    {
        {"rcert", required_argument, NULL, 'r'},
        {"rkeypair", required_argument, NULL, 'k'},
        {"skeypair", required_argument, NULL, 's'},
        {"reserved", required_argument, NULL, 'x'},
        {"out-servercert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "r:k:s:x:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'r':
                params->rootcert = optarg;
                break;
            case 'k':
                params->keypair = optarg;
                break;
            case 's':
                params->serverkeypair = optarg;
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
    params->serverkeypair = "server_keys.asn1.bin";
    params->daagpk = "daa_gpk.bin";

    const char *usage_str = "Run XTT server.\n\n"
        "Usage: %s %s [-h] [-p ####] [-d <file>] [-v <file>] [-b <file>][-c <file>]\n"
        "\tOptions:\n"
        "\t\t-h --help                    Display this message.\n"
        "\t\t-p --port                    Specifies which port to start the server on [default port: 4444]\n"
        "\t\t-d --daagpk                  Specifies where DAA GPK can be found [default = daa_gpk.bin]\n"
        "\t\t-k --skeypair                Specifies where server's key pair can be found [default = server_keys.asn1.bin]\n"
        "\t\t-b --basename                Specifies where the basename can be found [default = basename.bin]\n"
        "\t\t-c --servercert              Specifies where server certificate can be found [default = server_cert.bin]\n"
        ;

    static struct option cli_options[] =
    {
        {"port", required_argument, NULL, 'p'},
        {"daagpk", required_argument, NULL, 'd'},
        {"skeypair", required_argument, NULL, 'k'},
        {"basename", required_argument, NULL, 'b'},
        {"servercert", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:d:k:b:c:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                params->port = atoi(optarg);
                break;
            case 'd':
                params->daagpk = optarg;
                break;
            case 'k':
                params->serverkeypair = optarg;
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
    params->requestid = NULL;
    params->basename = "basename.bin";
    params->rootcert = "root_cert.bin";
    params->daagpk = "daa_gpk.bin";
    params->daacred = "daa_cred.bin";
    params->daasecretkey = "daa_secretkey.bin";
    params->usetpm = 0;
    params->suitespec = "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512";
#ifdef USE_TPM
    char *tcti_str = "device";
    params->tpm_params.dev_file = "/dev/tpm0";
    params->tpm_params.hostname = "localhost";
    params->tpm_params.port = "2321";
#endif
    const char *usage_str = "Run XTT client.\n\n"
        "Usage: %s %s [-h] [-p <file>] [-s option] [-a <file>] [-q <file>] [-r <file>] [-d <file>] [-c <file>] [-k <file>]"
        "[-e <file>] [-n <file>] [-i <file>] [b <file>] [-v <file>]"
#ifdef USE_TPM
        " [-m <file>] [-t <file>] [-f <file>]"
#endif
        "\n"
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
        "\t\t-i --assignedid              Assigned ID output location [default = client_id.txt]\n"
        "\t\t-b --longtermpub             Longterm Public Key output location [default = longterm_cert.bin]\n"
        "\t\t-v --longtermpriv            Longterm Private Key output location [default = longterm_priv.bin]\n"
#ifdef USE_TPM
        "\t\t-m --tpmuse                  Indicates to use TPM [default = false]\n"
        "\t\t-t --tctitype                Which TCTI socket is used ('device' or 'socket') [default = device]\n"
        "\t\t-f --devfile                 Device file input location if tcti == device [default = /dev/tpm0]\n"
#endif
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
        {"assignedid", required_argument, NULL, 'i'},
        {"longtermpub", required_argument, NULL, 'b'},
        {"longtermpriv", required_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
#ifdef USE_TPM
        {"tpmuse", no_argument, NULL, 'm'},
        {"tctitype", required_argument, NULL, 't'},
        {"devfile", required_argument, NULL, 'f'},
#endif

        {NULL, 0, NULL, 0}
    };
    bool nondefault_priv_file = false;
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
                nondefault_priv_file = true;
                break;
            }
#ifdef USE_TPM
            case 'm':
                params->usetpm = 1;
                break;
            case 't':
                tcti_str = optarg;
                break;
            case 'f':
                params->tpm_params.dev_file = optarg;
                break;
#else
            case 'm':
            case 't':
            case 'f':
                printf("TPM options are not supported, because not built with TPM support.");
                exit(1);
#endif
            case 'h':
            printf(usage_str, argv[0], argv[1]);
            exit(1);
        }
    }

#ifdef USE_TPM
    if (!nondefault_priv_file && 1 == params->usetpm)
        params->longtermpriv = "longterm_priv.pem";

    if (0 == strcmp(tcti_str, "device")) {
        params->tpm_params.tcti = XTT_TCTI_DEVICE;
    } else if (0 == strcmp(tcti_str, "socket")) {
        params->tpm_params.tcti = XTT_TCTI_SOCKET;
    } else {
        fprintf(stderr, "Unknown tcti_type '%s'\n", tcti_str);
        exit(1);
    }
#endif
}

static
void parse_nvram_cli(int argc, char** argv, struct cli_params *params)
{
#ifdef USE_TPM
    char *tcti_str = "device";
    params->tpm_params.dev_file = "/dev/tpm0";
    params->tpm_params.hostname = "localhost";
    params->tpm_params.port = "2321";
    params->outfile = NULL;
    const char *usage_str = "Dump to file an NVRAM object provisioned on a Xaptum TPM.\n\n"
        "Usage: %s [-h] [-t device|socket] [-d <path>] [-a <ip>] [-p <port>] [-o <file>] <object-name>\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-t --tcti              TPM TCTI type (device|socket) [default = device].\n"
        "\t\t-d --tpm-device-file   TCTI device file, if tcti==device [default = '/dev/tpm0'].\n"
        "\t\t-a --tpm-ip-address    IP hostname of TPM TCP server, if tcti==socket [default = 'localhost'].\n"
        "\t\t-p --tpm-port          TCP port of TPM TCP server, if tcti==socket [default = 2321].\n"
        "\t\t-o --output-file       Output file. [default: '<object-name>.[bin,pem]']\n"
        "\tArguments:\n"
        "\t\tobject-name\tOne of daa_gpk, daa_cred, daa_cred_sig, root_asn1_cert, root_xtt_cert, or basename\n"
        ;

    static struct option cli_options[] =
    {
        {"tcti", required_argument, NULL, 't'},
        {"tpm-device-file", required_argument, NULL, 'd'},
        {"tpm-ip-address", required_argument, NULL, 'a'},
        {"tpm-port", required_argument, NULL, 'p'},
        {"output-file", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "t:d:a:p:o:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 't':
                tcti_str = optarg;
                break;
            case 'd':
                params->tpm_params.dev_file = optarg;
                break;
            case 'a':
                params->tpm_params.hostname = optarg;
                break;
            case 'p':
                params->tpm_params.port = optarg;
                break;
            case 'o':
                params->outfile = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0]);
                exit(1);
        }
    }
    if (argv[optind] != NULL) {
        if (0 == strcmp(argv[optind], "daa_gpk")) {
            params->obj_name = XTT_GROUP_PUBLIC_KEY;
            if (params->outfile == NULL)
                params->outfile = "daa_gpk.bin";
        } else if (0 == strcmp(argv[optind], "daa_cred")) {
            params->obj_name = XTT_CREDENTIAL;
            if (params->outfile == NULL)
                params->outfile = "daa_cred.bin";
        } else if (0 == strcmp(argv[optind], "daa_cred_sig")) {
            params->obj_name = XTT_CREDENTIAL_SIGNATURE;
            if (params->outfile == NULL)
                params->outfile = "daa_cred_sig.bin";
        } else if (0 == strcmp(argv[optind], "root_asn1_cert")) {
            params->obj_name = XTT_ROOT_ASN1_CERTIFICATE;
            if (params->outfile == NULL)
                params->outfile = "root_asn1_cert.pem";
        } else if (0 == strcmp(argv[optind], "root_xtt_cert")) {
            params->obj_name = XTT_ROOT_XTT_CERTIFICATE;
            if (params->outfile == NULL)
                params->outfile = "root_xtt_cert.bin";
        } else if (0 == strcmp(argv[optind], "basename")) {
            params->obj_name = XTT_BASENAME;
            if (params->outfile == NULL)
                params->outfile = "basename.bin";
        } else {
            fprintf(stderr, "Unrecognized object name '%s'\n", argv[optind]);
            exit(1);
        }
    } else {
        fprintf(stderr, "Must specify object name\n");
        exit(1);
    }

    if (0 == strcmp(tcti_str, "device")) {
        params->tpm_params.tcti = XTT_TCTI_DEVICE;
    } else if (0 == strcmp(tcti_str, "socket")) {
        params->tpm_params.tcti = XTT_TCTI_SOCKET;
    } else {
        fprintf(stderr, "Unknown tcti_type '%s'\n", tcti_str);
        exit(1);
    }
#else
    (void)argc;
    (void)argv;
    (void)params;
    printf("NVRAM operations are not supported, because not built with TPM support.");
    exit(1);
#endif
}

void parse_cli(int argc, char** argv, struct cli_params *params)
{
    const char *usage_str =
        "Usage: %s [command] --command_options\n"
        "Commands:\n"
        "\tgenkeypair               Generate ECDSA keys for XTT.\n"
        "\tgenx509cert              Generate x509 certificate.\n"
        "\tgenrootcert              Generate root certificate.\n"
        "\tgenservercert            Generate server certificate and server private key.\n"
        "\trunserver                Run a XTT server.\n"
        "\trunclient                Run a XTT client.\n"
        "\tinfocert                 Get information about a certificate.\n"
        "\treadnvram                Read info from the TPM's NVRAM.\n"
        ;

    if(argc <=1 || strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        printf(usage_str, argv[0]);
        exit(1);
    }

    if(strcmp(argv[1], "genkeypair")==0)
    {
        params->command=action_genkey;
        parse_genkey_cli(argc, argv, params);
    } else if (strcmp(argv[1], "genx509cert")==0)
    {
        params->command=action_genx509cert;
        parse_genx509cert_cli(argc, argv, params);
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
    } else if (strcmp(argv[1], "readnvram")==0)
    {
        params->command=action_readnvram;
        parse_nvram_cli(argc-1, &argv[1], params);
    } else
    {
        fprintf(stderr, "'%s' is not an option for the XTT tool.\n", argv[1]);
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }
}
