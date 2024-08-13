#ifndef OPENSSL_NO_SECH
# ifndef HEADER_SECH_LOCAL_H
#  define HEADER_SECH_LOCAL_H
#  include <openssl/ssl.h>
#  include <openssl/ech.h>
#  include <openssl/hpke.h>
# include "ssl_local.h"


struct sech5_hpke_enc_in {
    unsigned char * clear;
    size_t clear_len;
    OSSL_HPKE_SUITE hpke_suite;
    unsigned char * pub;
    size_t pub_len;
    unsigned char * info;
    size_t info_len;
    unsigned char * aad;
    size_t aad_len;
};
struct sech5_hpke_enc_out {
    unsigned char * enc;
    size_t enc_len;
    unsigned char * ciphertext;
    size_t ciphertext_len;
};
int sech5_hpke_enc(SSL *s,
        const struct sech5_hpke_enc_in in,
        struct sech5_hpke_enc_out * out);
int sech5_make_ClientHelloInner(SSL_CONNECTION *s);

# endif//HEADER_SECH_LOCAL_H
#endif//OPENSSL_NO_SECH

