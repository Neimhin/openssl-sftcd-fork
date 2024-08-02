/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl/ssl_local.h"
#include "../ssl/ech_local.h"
#include "../ssl/sech_local.h"
// #include <openssl/ssl.h>
// #include <openssl/hpke.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#ifndef OPENSSL_NO_SECH

# define TEST_FAIL 0
# define TEST_PASS 1

/*
 * The command line argument one can provide is the location
 * of test certificates etc, which would be in $TOPDIR/test/certs
 * so if one runs "test/ech_test" from $TOPDIR, then we don't
 * need the command line argument at all.
 */
# define DEF_CERTS_DIR "test/certs"
# define OSSL_ECH_CRYPTO_VAR_SIZE 1024

static OSSL_LIB_CTX *libctx = NULL;
static BIO *bio_stdout = NULL;
static BIO *bio_null = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *rootcert = NULL;
static int verbose = 0;


X509 * load_cert(char*cert_file) {
    X509*cert = NULL;
    FILE*file = fopen(cert_file, "r");
    if(!file) return NULL;
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    return cert;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH tests\n" },
        { NULL }
    };
    return test_options;
}

int test_hpke_encrypt(int idx)
{
    int rv = 0;
    SSL* s = NULL;
    unsigned char clear[16] = {0};
    strcpy((char*)clear, "inner.com");
    size_t clear_len = sizeof(clear);
    unsigned char aad[] = "test-aad";
    size_t aad_len = sizeof(aad);
    OSSL_HPKE_SUITE hpke_suite =  OSSL_HPKE_SUITE_DEFAULT;
    unsigned char * enc = NULL;
    size_t enc_len = 0;
    unsigned char * payload = NULL;
    int subrv = 0;
    size_t publen = OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char pub[OSSL_ECH_CRYPTO_VAR_SIZE];
    size_t privlen= OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char priv[OSSL_ECH_CRYPTO_VAR_SIZE];

    unsigned char * info = "12345";
    SSL_CTX * sslctx = NULL;


    unsigned char echconfig[OSSL_ECH_MAX_ECHCONFIG_LEN];
    size_t echconfig_len = 0;
    uint16_t ech_version = OSSL_ECH_CURRENT_VERSION;
    uint16_t max_name_length = 63;
    unsigned char * public_name = "outer.com";
    unsigned char * extvals = NULL;
    size_t extlen = 0;
    EVP_PKEY * privp = NULL;

    OSSL_HPKE_CTX * ehctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE,
            hpke_suite,
            OSSL_HPKE_ROLE_RECEIVER,
            NULL, NULL);
    if(ehctx == NULL) {
        goto end;
    }
    if (OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp, NULL, 0, libctx, NULL)
        != 1) {
        rv = 0;
        goto end;
    }

    fprintf(stderr, "publen: %lu\n", publen);

    SSL_CTX *cctx = NULL, *sctx = NULL;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey))){
        rv = 0;
        goto end;
    }

    // subrv = OSSL_ech_make_echconfig(echconfig, &echconfig_len,
    //                         priv, &privlen,
    //                         ech_version, max_name_length,
    //                         public_name,
    //                         hpke_suite, extvals, extlen,
    //                         NULL, NULL);

    // if(subrv != 1) {
    //     TEST_info("failed to ech_make_echconfig");
    //     goto end;
    // }


    SSL_ECH * echs = NULL;
    int echs_len = 0;
    // subrv = local_ech_add(OSSL_ECH_FMT_GUESS, echconfig_len, echconfig, &echs_len, &echs);
    // if(subrv != 1) {

    //     goto end;
    // }
 
    // SSL_CTX_ech_set1_echconfig(sctx, echconfig, echconfig_len);
    // if(subrv != 1) {
    //     TEST_info("failed to set2_echconfig");
    //     goto end;
    // }

    // BIO_dump_fp(stderr, sctx->ext->ech->cfg->recs->pub, sctx->ext->ech->cfg->recs->pub);

    size_t info_len = 5;
    struct sech5_hpke_enc_out out = { 0 };
    {
        struct sech5_hpke_enc_in in = {
            .hpke_suite = hpke_suite,
            .clear = clear,
            .clear_len = clear_len,
            .pub = pub,
            .pub_len = publen,
            .info = info,
            .info_len = info_len,
            .aad = aad,
            .aad_len = aad_len,
        };
        subrv = sech5_hpke_enc(s,
                in,
                &out);
        if(subrv != 1) {
            rv = 0;
            goto end;
        }
        if(verbose) {
            fprintf(stderr, "clear in:\n");
            BIO_dump_fp(stderr, clear, clear_len);
            fprintf(stderr, "cipher in %lu:\n", out.ciphertext_len);
            BIO_dump_fp(stderr, out.ciphertext, out.ciphertext_len);
        }
    }
    if(subrv != 1) {
        if(verbose) TEST_info("failed sech5_hpke_enc");
        goto end;
    }
    if(verbose) {
        fprintf(stderr, "enc:\n");
        BIO_dump_fp(stderr, enc, enc_len);
    }

    {
        OSSL_HPKE_CTX * hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE,
                hpke_suite,
                OSSL_HPKE_ROLE_RECEIVER,
                NULL, NULL);
        if(hctx == NULL) {
            goto end;
        }
        subrv = OSSL_HPKE_decap(hctx, out.enc, out.enc_len, privp, info, info_len);
        if(subrv != 1) {
            goto end;
        }
        unsigned char pt[1024] = {0};
        size_t ptlen = out.ciphertext_len;
        subrv = OSSL_HPKE_open(hctx, 
                pt, &ptlen,
                aad, aad_len,
                out.ciphertext, out.ciphertext_len);
        if(subrv != 1) {
            TEST_info("failed OSSL_HPKE_open");
            goto end;
        }
        fprintf(stderr, "clear out:\n");
        BIO_dump_fp(stderr, pt, ptlen);
    }
    rv = 1;
end:
    OPENSSL_free(enc); enc = NULL;
    OPENSSL_free(payload); payload = NULL;
    return rv;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;
    cert = test_mk_file_path(certsdir, "echserver.pem");
    if (cert == NULL)
        goto err;
    privkey = test_mk_file_path(certsdir, "echserver.key");
    if (privkey == NULL)
        goto err;
    rootcert = test_mk_file_path(certsdir, "rootcert.pem");
    if (rootcert == NULL)
        goto err;
    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_ALL_TESTS(test_hpke_encrypt, 2);
    return 1;
err:
    return 0;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    BIO_free(bio_null);
    BIO_free(bio_stdout);
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(rootcert);
#endif
}
