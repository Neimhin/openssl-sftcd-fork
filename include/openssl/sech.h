
#ifndef OPENSSL_SECH_H
# define OPENSSL_SECH_H
# pragma once
#ifndef OPENSSL_NO_ECH
#  define SSL_SECH_STATUS_SUCCESS   1 /* tried and succeeded with stealthy ECH, either on server or client */
#  define SSL_SECH_STATUS_FAILED    0 /* generic failure of attempted SECH, either on server or client */
# include <openssl/ssl.h>
int SSL_CTX_set_sech_inner_servername(SSL_CTX *ctx, char* inner_servername, int inner_servername_len);
int SSL_CTX_set_sech_symmetric_key(SSL_CTX *ctx, const char * key, size_t key_len);
int SSL_CTX_set_sech_version(SSL_CTX *ctx, int version);
int SSL_get_sech_status(SSL * s, char **inner_sni, char **outer_sni);
#endif
#endif
