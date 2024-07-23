/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>
#include <openssl/sech.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
# define TEST_FAIL 0
# define TEST_PASS 1

/*
 * The command line argument one can provide is the location
 * of test certificates etc, which would be in $TOPDIR/test/certs
 * so if one runs "test/ech_test" from $TOPDIR, then we don't
 * need the command line argument at all.
 */
# define DEF_CERTS_DIR "test/certs"

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

/* Shuffle to preferred order */
enum OSSLTEST_ECH_ADD_runOrder
    {
     OSSLTEST_ECH_B64_GUESS,
     OSSLTEST_ECH_B64_BASE64,
     OSSLTEST_ECH_B64_GUESS_XS_COUNT,
     OSSLTEST_ECH_B64_GUESS_LO_COUNT,
     OSSLTEST_ECH_B64_JUNK_GUESS,

     OSSLTEST_ECH_NTESTS        /* Keep NTESTS last */
    };

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



int sech2_tried_but_not_accepted__servername_callback(SSL *s, int *al, void *arg)
{

    int servername_type = SSL_get_servername_type(s);
    const char * servername = SSL_get_servername(s, servername_type);
    if(verbose){
      fprintf(stderr, "servername_type: %i\n", servername_type);
      fprintf(stderr, "TLSEXT_NAMETYPE_host_name: %i\n", TLSEXT_NAMETYPE_host_name);
      fprintf(stderr, "servername: %s\n", servername);
    }
    return SSL_TLSEXT_ERR_OK;
}
// int sech2_tried_but_not_accepted__msg_callback(SSL *s, int *al, void *arg)
// {
// }
// - normal TLS1_3 server
// - client running SECH version 2
// - expect server to ignore inner SNI, returning valid certificate for outer SNI
static int sech2_tried_but_not_accepted(int idx)
{
    char * inner_servername = "inner.example";
    const char * expected_servername = "server.example";
    SSL_CTX *cctx = NULL, *sctx = NULL;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        return 0;
    SSL_CTX_set_sech_version(cctx, 2);
    char key[4] = {0xab, 0xab, 0xab, 0xab};
    size_t key_len = sizeof(key);
    SSL_CTX_set_sech_symmetric_key(cctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_inner_servername(cctx, inner_servername, 0); // len = 0 -> use strlen
    SSL_CTX_set_tlsext_servername_callback(sctx, sech2_tried_but_not_accepted__servername_callback);
    SSL * serverssl = NULL;
    SSL * clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)))
        return 0;
    if (verbose) fprintf(stderr, "%p\n", sctx);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))) return 0;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, expected_servername))) return 0;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))) return 0;

    // confirm that the returned certificate is for the 'outer' server.example
    X509 * server_certificate = SSL_get_peer_certificate(clientssl);
    X509 * client_certificate = SSL_get_certificate(clientssl);
    if(verbose) X509_print_ex_fp(stderr, server_certificate, 0, 0);
    if(server_certificate == NULL) {
        // shouldn't happen?
        return 0;
    }
    int check_host = X509_check_host(server_certificate, expected_servername, 0, 0, NULL);
    if(check_host != 1) {
        return 0;
    }
    if(client_certificate == NULL) { /* that's fine */ }

    X509_NAME *verified_server_name = X509_get_subject_name(server_certificate);

    if(!X509_NAME_print_ex_fp(stderr, verified_server_name, 0, 0)) {
        return 0;
    };
    char*name = X509_NAME_oneline(verified_server_name, NULL, 0); // buf=NULL -> size=0 is ignored
    if(name == NULL) {
        return 0;
    }

    if(verbose)fprintf(stderr, "\n%i", name[0]);
    if(verbose)fprintf(stderr, "\n%s\n", name);

    int cmp = strcmp("/CN=server.example", name);
    if(verbose)fprintf(stderr, "strcmp(\"/CN=server.example\",\"%s\") = %i\n", name ,cmp);
    if(cmp == 0)  return 1;
    return 0;
}

static int sech2_sanity_check_certs(int idx)
{
    // char * inner_cert = test_mk_file_path(certsdir, "inner.crt");
    // char * inner_key  = test_mk_file_path(certsdir, "inner.key");
    char * outer_cert = test_mk_file_path(certsdir, "outer.crt");
    char * outer_key  = test_mk_file_path(certsdir, "outer.key");
    char * inner_servername = "inner.com";
    char * outer_servername = "outer.com";
    SSL_CTX *cctx = NULL, *sctx = NULL;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, outer_cert, outer_key)))
        return 0;
    SSL_CTX_set_sech_version(cctx, 2);
    char key[4] = {0xab, 0xab, 0xab, 0xab};
    size_t key_len = sizeof(key);
    SSL_CTX_set_sech_symmetric_key(cctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_inner_servername(cctx, inner_servername, 0); // len = 0 -> use strlen
    SSL_CTX_set_sech_symmetric_key(sctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(sctx, 2);
    SSL_CTX_set_sech_inner_servername(sctx, inner_servername, 0); // len = 0 -> use strlen
    // SSL_CTX_set_sech_inner_servername(...);
    SSL * serverssl = SSL_new(sctx);
    SSL * clientssl = SSL_new(cctx);
    SSL_CTX_set_tlsext_servername_callback(sctx, sech2_tried_but_not_accepted__servername_callback);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))) return 0;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, outer_servername))) return 0;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))) return 0;

    // confirm that the returned certificate is for the 'outer' server.example
    X509 * server_certificate = SSL_get_peer_certificate(clientssl);
    if(verbose) X509_print_ex_fp(stderr, server_certificate, 0, 0);
    if(server_certificate == NULL) {
        // shouldn't happen?
        return 0;
    }
    int check_host = X509_check_host(server_certificate, outer_servername, 0, 0, NULL);
    if(check_host != 1) {
        return 0;
    }
    return 1;
}

typedef struct {
    X509 * inner_cert;
    SSL_CTX * inner_ctx;
} SECH_SERVERNAME_ARG;

int sech2_roundtrip_accept__servername_cb(SSL *s, int *al, void *arg)
{
    if(verbose)fprintf(stderr, "sech2_roundtrip_accept__servername_cb\n");
    char * inner_sni = NULL;
    char * outer_sni = NULL;
    SECH_SERVERNAME_ARG * servername_arg = (SECH_SERVERNAME_ARG*) arg;
    const char * servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    int sechrv = SSL_get_sech_status(s, &inner_sni, &outer_sni);
    if(verbose) fprintf(stderr, "sechrv: %i\n", sechrv);
    if(verbose) fprintf(stderr, "servername: %s\n", servername);
    if(servername != NULL && sechrv == SSL_SECH_STATUS_SUCCESS)
    {
      int check_host = X509_check_host(servername_arg->inner_cert, servername, 0, 0, NULL);
      if(check_host == 1)
      {
          if(verbose)fprintf(stderr, "sech2_roundtrip_accept__servername_cb: switching context\n");
          SSL_set_SSL_CTX(s, servername_arg->inner_ctx);
      } else
      {
          if(verbose)fprintf(stderr, "sech2_roundtrip_accept__servername_cb: using main context\n");
      }
    }

    if(verbose)fprintf(stderr, "inner_ctx set\n");
    return 1;
}

struct sech_key {
    char data[32];
    size_t length;
};

static const struct sech_key key1 = {
    .data = {
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
    },
    .length = 32,
};

static const struct sech_key key2 = {
    .data = {
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
    },
    .length = 32,
};

struct sech_roundtrip_expect {
    char check_host[256];
    int client_status;
    int server_status;
};

struct sech_roundtrip_opt {
    char force_hrr;
    char * certsdir;
    char * inner_cert_file;
    int (*servername_cb)(SSL*s, int*al, void*arg);
    struct sech_key client_key;
    struct sech_key server_key;
    struct sech_roundtrip_expect expect;
};

static const inline struct sech_roundtrip_opt default_opt()
{
    struct sech_roundtrip_opt opt = {
        .force_hrr = 0,
        .certsdir = certsdir,
        .inner_cert_file = "inner.crt",
        .servername_cb = sech2_roundtrip_accept__servername_cb,
        .client_key = key1,
        .server_key = key1,
        .expect = {
            .check_host = "inner.com",
            .client_status = SSL_SECH_STATUS_SUCCESS,
            .server_status = SSL_SECH_STATUS_SUCCESS,
        }
    };
    return opt;
}


static int sech2_roundtrip(int idx, struct sech_roundtrip_opt opt)
{
    char * inner_cert_file = test_mk_file_path(opt.certsdir, opt.inner_cert_file);
    char * inner_key_file  = test_mk_file_path(opt.certsdir, "inner.key");
    char * outer_cert_file = test_mk_file_path(opt.certsdir, "outer.crt");
    char * outer_key_file  = test_mk_file_path(opt.certsdir, "outer.key");
    char * inner_servername = "inner.com";
    char * outer_servername = "outer.com";
    X509 * inner_cert = load_cert(inner_cert_file);
    if(inner_cert == NULL) return 0;

    if(verbose) {
      X509_NAME *subject = X509_get_subject_name(inner_cert);
      if (subject) {
          char *subject_str = X509_NAME_oneline(subject, NULL, 0);
          if (subject_str) {
              printf("Inner certificate subject: %s\n", subject_str);
              OPENSSL_free(subject_str);
          }
      }
    }


    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL_CTX *inner_sctx = NULL;
    inner_sctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if(!TEST_ptr(inner_sctx)) return 0; // TODO cleanup/free
    SECH_SERVERNAME_ARG servername_arg = {.inner_cert=inner_cert, .inner_ctx=inner_sctx}; 
    SSL_CTX_set_min_proto_version(inner_sctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(inner_sctx, TLS1_3_VERSION);
    if(!TEST_int_eq(SSL_CTX_use_certificate(inner_sctx, inner_cert), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_use_PrivateKey_file(inner_sctx, inner_key_file, SSL_FILETYPE_PEM), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_check_private_key(inner_sctx), 1)) return 0; // TODO cleanup/free

    if(verbose) fprintf(stderr, "inner_sctx private key checked\n");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, outer_cert_file, outer_key_file)))
        return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx, opt.servername_cb))) return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, (void*) &servername_arg))) return 0;
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_symmetric_key(sctx, opt.server_key.data, opt.server_key.length);
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_inner_servername(cctx, inner_servername, 0); // len = 0 -> use strlen
    SSL_CTX_set_sech_symmetric_key(cctx, opt.client_key.data, opt.client_key.length);
    SSL_CTX_set_sech_version(sctx, 2);
    SSL_CTX_set_sech_inner_servername(sctx, inner_servername, 0); // len = 0 -> use strlen
    SSL * serverssl = NULL;
    SSL * clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)))                              return 0;

    if (opt.force_hrr && !TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
        return 0;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, outer_servername)))                                           return 0;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))                                     return 0;
    X509 * server_certificate = SSL_get_peer_certificate(clientssl);
    // if(verbose) X509_print_ex_fp(stderr, server_certificate, 0, 0);
    if(server_certificate == NULL) return 0;
    int check_host = X509_check_host(server_certificate, opt.expect.check_host, 0, 0, NULL);
    if(check_host != 1) {
        if(verbose)
            TEST_info("sech2_roundtrip got wrong outer_servername: expected %s: check_host=%i\n", opt.expect.check_host, check_host);
        return 0;
    }

    char * client_inner_sni = NULL, * client_outer_sni = NULL;
    char * server_inner_sni = NULL, * server_outer_sni = NULL;
    int client_status = SSL_get_sech_status(clientssl, &client_inner_sni, &client_outer_sni);
    int server_status = SSL_get_sech_status(serverssl, &server_inner_sni, &server_outer_sni);
    if(!TEST_int_eq(client_status, opt.expect.client_status)) return 0;
    if(!TEST_int_eq(server_status, opt.expect.server_status)) return 0;

    X509_free(inner_cert);
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    if(verbose)fprintf(stderr, "FINISHED SECH2 ROUNDTRIP\n");
    return 1;
}

static int test_sech2_roundtrip_accept(int idx)
{
    struct sech_roundtrip_opt opt = default_opt();
    return sech2_roundtrip(idx, opt);
}

static int test_sech2_roundtrip_reject(int idx)
{
    struct sech_roundtrip_opt opt = default_opt();
    opt.server_key = key2;
    memcpy(opt.expect.check_host, "outer.com", sizeof("outer.com"));
    opt.expect.client_status = SSL_SECH_STATUS_FAILED;
    opt.expect.server_status = SSL_SECH_STATUS_FAILED;
    return sech2_roundtrip(idx, opt);
}

static int test_sech2_roundtrip_hrr_accept(int idx)
{
    struct sech_roundtrip_opt opt = default_opt();
    opt.force_hrr = 1;
    return sech2_roundtrip(idx, opt);
}

static int test_sech2_roundtrip_hrr_reject(int idx)
{
    struct sech_roundtrip_opt opt = default_opt();
    opt.force_hrr = 1;
    opt.server_key = key2;
    memcpy(opt.expect.check_host, "outer.com", sizeof("outer.com"));
    opt.expect.client_status = SSL_SECH_STATUS_FAILED;
    opt.expect.server_status = SSL_SECH_STATUS_FAILED;
    return sech2_roundtrip(idx, opt);
}

static int sech2_roundtrip_accept(int idx)
{
    char * inner_cert_file = test_mk_file_path(certsdir, "inner.crt");
    char * inner_key_file  = test_mk_file_path(certsdir, "inner.key");
    char * outer_cert_file = test_mk_file_path(certsdir, "outer.crt");
    char * outer_key_file  = test_mk_file_path(certsdir, "outer.key");
    char * inner_servername = "inner.com";
    char * outer_servername = "outer.com";
    X509 * inner_cert = load_cert(inner_cert_file);
    if(inner_cert == NULL) return 0;

    if(verbose) {
      X509_NAME *subject = X509_get_subject_name(inner_cert);
      if (subject) {
          char *subject_str = X509_NAME_oneline(subject, NULL, 0);
          if (subject_str) {
              printf("Inner certificate subject: %s\n", subject_str);
              OPENSSL_free(subject_str);
          }
      }
    }


    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL_CTX *inner_sctx = NULL;
    inner_sctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if(!TEST_ptr(inner_sctx)) return 0; // TODO cleanup/free
    SECH_SERVERNAME_ARG servername_arg = {.inner_cert=inner_cert, .inner_ctx=inner_sctx}; 
    SSL_CTX_set_min_proto_version(inner_sctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(inner_sctx, TLS1_3_VERSION);
    if(!TEST_int_eq(SSL_CTX_use_certificate(inner_sctx, inner_cert), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_use_PrivateKey_file(inner_sctx, inner_key_file, SSL_FILETYPE_PEM), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_check_private_key(inner_sctx), 1)) return 0; // TODO cleanup/free

    if(verbose) fprintf(stderr, "inner_sctx private key checked\n");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, outer_cert_file, outer_key_file)))
        return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx, sech2_roundtrip_accept__servername_cb))) return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, (void*) &servername_arg))) return 0;
    SSL_CTX_set_sech_version(cctx, 2);
    char key[32] = {
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
    };
    size_t key_len = sizeof(key);
    SSL_CTX_set_sech_symmetric_key(cctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_inner_servername(cctx, inner_servername, 0); // len = 0 -> use strlen
    SSL_CTX_set_sech_symmetric_key(sctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(sctx, 2);
    SSL_CTX_set_sech_inner_servername(sctx, inner_servername, 0); // len = 0 -> use strlen
    SSL * serverssl = NULL;
    SSL * clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)))                              return 0;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, outer_servername)))                                           return 0;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))                                     return 0;
    X509 * server_certificate = SSL_get_peer_certificate(clientssl);
    // if(verbose) X509_print_ex_fp(stderr, server_certificate, 0, 0);
    if(server_certificate == NULL) return 0;
    int check_host = X509_check_host(server_certificate, inner_servername, 0, 0, NULL);
    if(!TEST_true(check_host == 1)) {
        if(verbose)
            TEST_info("sech2_roundtrip_accept got wrong outer_servername: expected %s: check_host=%i\n", inner_servername, check_host);
        return 0;
    }

    char * client_inner_sni = NULL, * client_outer_sni = NULL;
    char * server_inner_sni = NULL, * server_outer_sni = NULL;
    int client_status = SSL_get_sech_status(clientssl, &client_inner_sni, &client_outer_sni);
    int server_status = SSL_get_sech_status(serverssl, &server_inner_sni, &server_outer_sni);
    if(!TEST_int_eq(client_status, SSL_SECH_STATUS_SUCCESS)) return 0;
    if(!TEST_int_eq(server_status, SSL_SECH_STATUS_SUCCESS)) return 0;
    return 1;
}

int sech2_roundtrip_wrong_key__servername_cb(SSL *s, int *al, void *arg)
{
    if(verbose)fprintf(stderr, "sech2_roundtrip_wrong_key__servername_cb\n");
    char * inner_sni = NULL;
    char * outer_sni = NULL;
    SECH_SERVERNAME_ARG * servername_arg = (SECH_SERVERNAME_ARG*) arg;
    const char * servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    int sechrv = SSL_get_sech_status(s, &inner_sni, &outer_sni);
    if(verbose) fprintf(stderr, "sechrv: %i\n", sechrv);
    if(servername != NULL && sechrv == SSL_SECH_STATUS_SUCCESS)
    {
      int check_host = X509_check_host(servername_arg->inner_cert, servername, 0, 0, NULL);
      if(check_host == 1)
      {
          if(verbose)fprintf(stderr, "sech2_roundtrip_wrong_key__servername_cb: switching context\n");
          SSL_set_SSL_CTX(s, servername_arg->inner_ctx);
      } else
      {
          if(verbose)fprintf(stderr, "sech2_roundtrip_wrong_key__servername_cb: using main context\n");
      }
    }

    if(verbose)fprintf(stderr, "inner_ctx set\n");
    return 1;
}

static int sech2_roundtrip_wrong_key(int idx)
{
    char * inner_cert_file = test_mk_file_path(certsdir, "inner.crt");
    char * inner_key_file  = test_mk_file_path(certsdir, "inner.key");
    char * outer_cert_file = test_mk_file_path(certsdir, "outer.crt");
    char * outer_key_file  = test_mk_file_path(certsdir, "outer.key");
    char * inner_servername = "inner.com";
    char * outer_servername = "outer.com";
    X509 * inner_cert = load_cert(inner_cert_file);
    if(inner_cert == NULL) return 0;

    if(verbose) {
      X509_NAME *subject = X509_get_subject_name(inner_cert);
      if (subject) {
          char *subject_str = X509_NAME_oneline(subject, NULL, 0);
          if (subject_str) {
              printf("Inner certificate subject: %s\n", subject_str);
              OPENSSL_free(subject_str);
          }
      }
    }


    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL_CTX *inner_sctx = NULL;
    inner_sctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if(!TEST_ptr(inner_sctx)) return 0; // TODO cleanup/free
    SECH_SERVERNAME_ARG servername_arg = {.inner_cert=inner_cert, .inner_ctx=inner_sctx}; 
    SSL_CTX_set_min_proto_version(inner_sctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(inner_sctx, TLS1_3_VERSION);
    if(!TEST_int_eq(SSL_CTX_use_certificate(inner_sctx, inner_cert), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_use_PrivateKey_file(inner_sctx, inner_key_file, SSL_FILETYPE_PEM), 1)) return 0; // TODO cleanup/free
    if(!TEST_int_eq(SSL_CTX_check_private_key(inner_sctx), 1)) return 0; // TODO cleanup/free

    if(verbose) fprintf(stderr, "inner_sctx private key checked\n");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, outer_cert_file, outer_key_file)))
        return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx, sech2_roundtrip_wrong_key__servername_cb))) return 0;
    if (!TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, (void*) &servername_arg))) return 0;
    SSL_CTX_set_sech_version(cctx, 2);
    char key[32] = {
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab,
    };
    char server_key[32] = {
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
        0xba, 0xba, 0xba, 0xba,
    };
    size_t key_len = sizeof(key);
    size_t server_key_len = sizeof(server_key);
    SSL_CTX_set_sech_symmetric_key(cctx, (char*)key, key_len);
    SSL_CTX_set_sech_version(cctx, 2);
    SSL_CTX_set_sech_inner_servername(cctx, inner_servername, 0); // len = 0 -> use strlen
    SSL_CTX_set_sech_symmetric_key(sctx, (char*)server_key, server_key_len);
    SSL_CTX_set_sech_version(sctx, 2);
    SSL_CTX_set_sech_inner_servername(sctx, inner_servername, 0); // len = 0 -> use strlen
    SSL * serverssl = NULL;
    SSL * clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)))                              return 0;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, outer_servername)))                                           return 0;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))                                     return 0;
    X509 * server_certificate = SSL_get_peer_certificate(clientssl);
    if(verbose) X509_print_ex_fp(stderr, server_certificate, 0, 0);
    if(server_certificate == NULL) return 0;
    int check_host = X509_check_host(server_certificate, outer_servername, 0, 0, NULL);
    if(check_host != 1) {
        if(verbose)
            TEST_info("sech2_roundtrip_wrong_key got wrong servername in server cert: expected %s: check_host=%i\n", inner_servername, check_host);
        return 0;
    }

    char * client_inner_sni = NULL, * client_outer_sni = NULL;
    char * server_inner_sni = NULL, * server_outer_sni = NULL;
    int client_status = SSL_get_sech_status(clientssl, &client_inner_sni, &client_outer_sni);
    int server_status = SSL_get_sech_status(serverssl, &server_inner_sni, &server_outer_sni);
    if(!TEST_int_eq(client_status, SSL_SECH_STATUS_FAILED)) return 0;
    if(!TEST_int_eq(server_status, SSL_SECH_STATUS_FAILED)) return 0;
    return 1;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
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
    /*
     * test a roundtrip for all suites, the test iteration
     * number is split into kem, kdf and aead string indices
     * to select the specific suite for that iteration
     */
    ADD_ALL_TESTS(sech2_tried_but_not_accepted, 2);
    ADD_ALL_TESTS(sech2_sanity_check_certs, 1);
    ADD_ALL_TESTS(sech2_roundtrip_wrong_key, 2);
    ADD_ALL_TESTS(test_sech2_roundtrip_accept, 2);
    ADD_ALL_TESTS(test_sech2_roundtrip_reject, 2);
    ADD_ALL_TESTS(test_sech2_roundtrip_hrr_accept, 2);
    ADD_ALL_TESTS(sech2_roundtrip_accept, 2);
    ADD_ALL_TESTS(test_sech2_roundtrip_hrr_reject, 2);
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
