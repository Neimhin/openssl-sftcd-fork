
#ifndef OPENSSL_SECH_H
# define OPENSSL_SECH_H
# pragma once
#ifndef OPENSSL_NO_ECH

/* generic failure of attempted SECH, either on server or client */
#  define SSL_SECH_STATUS_FAILED    0

/* tried and succeeded with stealthy ECH, either on server or client */
#  define SSL_SECH_STATUS_SUCCESS   1

/* did not attempt to offer/accept SECH */
#  define SSL_SECH_NOT_ATTEMPTED   2

/* SECH was offered but abandoned because HRR was needed, continued
 * normal TLS 1.3 handshake as cover */
#  define SSL_SECH_STATUS_ABANDONDED_HRR   3

# include <openssl/ssl.h>
int SSL_CTX_set_sech_inner_servername(SSL_CTX *ctx, char* inner_servername, int inner_servername_len);
int SSL_CTX_set_sech_symmetric_key(SSL_CTX *ctx, const char * key, size_t key_len);
int SSL_CTX_set_sech_version(SSL_CTX *ctx, int version);
int SSL_set_sech_version(SSL *s, int version);
int SSL_set_sech_symmetric_key(SSL *ssl, const char *key, size_t key_len);
int SSL_get_sech_status(SSL * s, char **inner_sni, char **outer_sni);
int SSL_CTX_sech_set1_sechconfig(SSL_CTX *ctx, const unsigned char *val,
                               size_t len);
int SSL_CTX_sech_server_enable_file(SSL_CTX *ctx, const char *pemfile,
                                   int for_retry);
#endif
#endif
