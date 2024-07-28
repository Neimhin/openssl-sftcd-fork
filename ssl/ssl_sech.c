#include <openssl/ech.h>
#include <openssl/rand.h>
#include "internal/packet.h"
#include "ssl_local.h"
#include "ech_local.h"
#ifndef OPENSSL_NO_ECH
#include <openssl/sech.h>


int sech_helper_encrypt(
    SSL * s,
    unsigned char * plain,
    size_t plain_len,
    unsigned char * key,
    size_t key_len,
    unsigned char ** iv,
    size_t * iv_len,
    unsigned char ** cipher_text,
    size_t * cipher_text_len,
    unsigned char ** tag,
    size_t * tag_len,
    char * cipher_suite)
{
    int ret = 0;
    unsigned char outbuf[1024];
    int outlen, tmplen;
    unsigned char * iv_out = NULL;
    size_t tagl = *tag_len;
    if(cipher_suite == NULL) cipher_suite = "AES-128-GCM";
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER * cipher = NULL;
    ctx = EVP_CIPHER_CTX_new();
    if(iv == NULL) goto end; // not allowed, must pass a pointer so the iv used can be returned
    if ((cipher = EVP_CIPHER_fetch(NULL, cipher_suite, NULL)) == NULL) goto end;
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, *iv == NULL ? NULL : *iv, NULL)) goto end;
    if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, plain, plain_len)) goto end;
    *iv_len = EVP_CIPHER_CTX_get_iv_length(ctx);
    iv_out = OPENSSL_malloc(*iv_len);
    if(iv_out == NULL) goto end;
    *iv= iv_out;
    if(!EVP_CIPHER_CTX_get_updated_iv(ctx, iv_out, *iv_len)) goto end;
    if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) goto end;
    
    if(tagl == 0) tagl = 16;
    *tag = OPENSSL_malloc(tagl);
    if(*tag == NULL) goto end;
    *tag_len = tagl;
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag)) goto end;
    outlen += tmplen;
    *cipher_text = OPENSSL_malloc(outlen + 1);
    if (cipher_text == NULL) goto end;
    memcpy(*cipher_text, outbuf, outlen);
    *cipher_text_len = outlen;
    ret = 1;
end:
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}
void sech_debug_buffer(char*msg, const unsigned char*buf, size_t blen) {
// #ifdef SECH_DEBUG
    BIO_dump_fp(stderr, buf, blen);
    fprintf(stderr, "%s:\t", msg);
    EVP_MD_CTX * ctx;
    const EVP_MD * md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    unsigned char base64_hash[EVP_ENCODE_LENGTH(EVP_MAX_MD_SIZE)];
    if (md == NULL) {
        fprintf(stderr, "debug_buffer failed\n");
        return;
    }
    hash_len = EVP_MD_size(md);
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, buf, blen) <= 0
        || EVP_DigestFinal_ex(ctx, hash, &hash_len) <= 0) {
        fprintf(stderr, "debug_buffer failed\n");
        return;
    }
    int base64_len = EVP_EncodeBlock((unsigned char *)base64_hash, hash, hash_len);
    if (base64_len <= 0) {
        fprintf(stderr, "debug_buffer base64 encoding failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    base64_hash[13]=0;
    fprintf(stderr, "(%i) %s\n", blen, base64_hash);
    BIO_dump_fp(stderr, buf, blen);
// #endif//SECH_DEBUG
}

int SSL_get_sech_status(SSL * ssl, char **inner_sni, char **outer_sni)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    if(s->ext.sech_peer_inner_servername != NULL) {
        *inner_sni = s->ext.sech_peer_inner_servername; // TODO should copy
        // TODO get outer SNI
        return SSL_SECH_STATUS_SUCCESS;
    }
    return SSL_SECH_STATUS_FAILED;
}

int SSL_CTX_set_sech_version(SSL_CTX *ctx, int version)
{
  switch(version)
  {
    case 2:
    case 0: // no sech
        ctx->ext.sech_version = version;
        return 1;
    default:
        return 0;
  }
}

int SSL_set_sech_version(SSL *ctx, int version)
{
  SSL_CONNECTION * s = SSL_CONNECTION_FROM_SSL(ctx);
  switch(version)
  {
    case 2:
    case 0: // no sech
        s->ext.sech_version = version;
        return 1;
    default:
        return 0;
  }
}

int SSL_CTX_set_sech_symmetric_key(SSL_CTX *ctx, const char *key, size_t key_len)
{
    if (key == NULL) return 0;
    if (ctx == NULL) return 0;
    ctx->ext.sech_symmetric_key = OPENSSL_memdup(key, key_len);
    if(ctx->ext.sech_symmetric_key == NULL) return 0;
    ctx->ext.sech_symmetric_key_len = key_len;
    return 1;
}

int SSL_set_sech_symmetric_key(SSL *ssl, const char *key, size_t key_len)
{
    SSL_CONNECTION * s = SSL_CONNECTION_FROM_SSL(ssl);
    if (key == NULL) return 0;
    if (s == NULL) return 0;
    s->ext.sech_symmetric_key = OPENSSL_memdup(key, key_len);
    if(s->ext.sech_symmetric_key == NULL) return 0;
    s->ext.sech_symmetric_key_len = key_len;
    return 1;
}

int SSL_CTX_set_sech_inner_servername(SSL_CTX *ctx, char* inner_servername, int inner_servername_len)
{
    if(inner_servername_len == 0 && inner_servername != NULL) {
      inner_servername_len = strlen(inner_servername);
    }
    ctx->ext.sech_inner_servername_len = inner_servername_len;
    ctx->ext.sech_inner_servername = OPENSSL_strdup(inner_servername);
    return 1;
}

int SSL_set_sech_inner_servername(SSL *ssl, char* inner_servername, int inner_servername_len)
{
    SSL_CONNECTION * s = SSL_CONNECTION_FROM_SSL(ssl);
    if(inner_servername_len == 0 && inner_servername != NULL) {
      inner_servername_len = strlen(inner_servername);
    }
    s->ext.sech_inner_servername_len = inner_servername_len;
    s->ext.sech_inner_servername = OPENSSL_strdup(inner_servername);
    return 1;
}

int sech2_edit_client_hello(SSL_CONNECTION *s, WPACKET *pkt) {
    size_t written;
    if(!WPACKET_get_total_written(pkt, &written)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    unsigned char * ch = WPACKET_get_curr(pkt) - written;
    unsigned char * p = ch + 4 + 2;
    unsigned char * iv = p;
    unsigned char * tag = NULL;
    size_t tag_len = 16;
    size_t iv_len = 12;
    s->ext.sech_inner_random = OPENSSL_malloc(OSSL_SECH2_INNER_RANDOM_LEN);
    unsigned char * key = s->ext.sech_session_key.data;
    size_t key_len = sizeof(s->ext.sech_session_key.data);
    SSL_CTX *sctx = SSL_CONNECTION_GET_CTX(s);
    if(RAND_bytes_ex(sctx->libctx, s->ext.sech_inner_random, OSSL_SECH2_INNER_RANDOM_LEN, RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    {
        void * dst = s->ext.sech_plain_text.data;
        void * src = s->ext.sech_inner_servername;
        int len = strlen(src);
        memcpy(dst, src, len); // TODO max strlen 36
    }
    {
        void * dst = s->ext.sech_plain_text.data + OSSL_SECH2_INNER_DATA_LEN;
        void * src = s->ext.sech_inner_random; 
        int len = OSSL_SECH2_INNER_RANDOM_LEN;
        memcpy(dst, src, len);
    }

    if(1 != sech_helper_encrypt(
        NULL,                   // SSL * s,
        s->ext.sech_plain_text.data, // unsigned char * plain,
        sizeof(s->ext.sech_plain_text.data),  // int plain_len,
        key,                    // unsigned char * key,
        key_len,                // int key_len,
        &iv,                    // unsigned char ** iv,
        &iv_len,                // int * iv_len,
        &(s->ext.sech_cipher_text),           // unsigned char ** cipher_text,
        &(s->ext.sech_cipher_text_len),       // int * cipher_text_len,
        &tag,                   // char ** tag,
        &tag_len,               // size_t * tag_len,
        NULL                    // char * cipher_suite) -> NULL use default AES-128-GCM
    )) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    else {
      s->ext.sech_plain_text.ready = 1;
      OPENSSL_assert(iv_len == sizeof(s->ext.sech_aead_nonce.data)); // iv_len is fixed in protocol (no negotiation))
      memcpy(s->ext.sech_aead_nonce.data, iv, iv_len);
      if((iv_len + s->ext.sech_cipher_text_len + tag_len) != (SSL3_RANDOM_SIZE + 32))
      { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return 0; }

      BIO_dump_fp(stderr, ch, written);
      unsigned char * session_id = p + 32 + 1;
      size_t first_part_len = SSL3_RANDOM_SIZE - OSSL_SECH2_AEAD_NONCE_LEN;
      size_t second_part_len = 32 - OSSL_SECH2_AEAD_TAG_LEN;
      memcpy(p, iv, iv_len);
      memcpy(p+iv_len, s->ext.sech_cipher_text, first_part_len);
      memcpy(session_id, s->ext.sech_cipher_text + first_part_len, second_part_len);
      memcpy(session_id + 16, tag, 16);
      memcpy(s->ext.sech_aead_tag.data, tag, 16);
      memcpy(s->s3.client_random, p, 32);
      memcpy(s->tmp_session_id, session_id, 32);
      BIO_dump_fp(stderr, ch, written);
      s->ext.sech_aead_tag.ready = 1;
      s->ext.sech_client_hello_transcript_for_confirmation = OPENSSL_memdup(ch, written);
      s->ext.sech_client_hello_transcript_for_confirmation_len = written;
      OPENSSL_assert((written >> 24) == 0); // assert length fits in uint24
      unsigned char * length_field = s->ext.sech_client_hello_transcript_for_confirmation + 1;
      size_t len = written - 4;
      length_field[0] = (len >> 16) & 0xFF; // Most significant byte
      length_field[1] = (len >> 8) & 0xFF;  // Middle byte
      length_field[2] = len & 0xFF;         // Least significant byte55);
      OPENSSL_free(iv);
    }
    return 1;
}

int sech2_make_ClientHelloOuterContext_client(SSL_CONNECTION *s, WPACKET *pkt)
{
    size_t written;
    if(!WPACKET_get_total_written(pkt, &written)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return CON_FUNC_ERROR;
    }
    unsigned char * ch = WPACKET_get_curr(pkt) - written;
    const size_t session_id_len = s->tmp_session_id_len;
    const size_t len = written - 4;
    ch[1] = (len >> 16) & 0xFF;
    ch[2] = (len >> 8) & 0xFF;
    ch[3] = len & 0xFF;
    return sech2_make_ClientHelloOuterContext(s, ch, written, session_id_len);
}

int sech2_make_ClientHello2_client(SSL_CONNECTION *s, WPACKET *pkt)
{
    size_t written;
    if(!WPACKET_get_total_written(pkt, &written)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return CON_FUNC_ERROR;
    }
    unsigned char * ch = WPACKET_get_curr(pkt) - written;
    s->ext.sech_ClientHello2 = OPENSSL_memdup(ch, written);
    if(!s->ext.sech_ClientHello2) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    fprintf(stderr, "ClientHello2 length on client: %i\n", written);
    unsigned char * length_field = s->ext.sech_ClientHello2 + 1;
    size_t len = written - 4;
    OPENSSL_assert((len >> 24) == 0);
    length_field[0] = (len >> 16) & 0xFF; // Most significant byte
    length_field[1] = (len >> 8) & 0xFF;  // Middle byte
    length_field[2] = len & 0xFF;         // Least significant byte55);
    s->ext.sech_ClientHello2_len = written;
    return 1;
}

int sech2_make_ClientHello2_server(SSL_CONNECTION *s, PACKET *pkt)
{
    return 0;
}

int sech2_derive_session_key(SSL_CONNECTION *s)
{
    int rv = 0;
    EVP_MD_CTX * ctx;
    const EVP_MD * md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (md == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    hash_len = EVP_MD_size(md);
    unsigned char * tbuf = s->ext.sech_ClientHelloOuterContext;
    size_t tlen = s->ext.sech_ClientHelloOuterContext_len;
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
        || EVP_DigestFinal_ex(ctx, hash, &hash_len) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    const unsigned char * expansion_label = (unsigned char *) "sech2 session";
    size_t labellen = sizeof("sech2 session");
    if (!tls13_hkdf_expand(
                s,                                       // SSL_CONNECTION *s,                            
                md,                                      // const EVP_MD *md,
                s->ext.sech_symmetric_key,                               // const unsigned char *secret, // TODO HKDF-Extract secret
                expansion_label, labellen,  // const unsigned char *label, size_t labellen,
                hash, hash_len,                        // const unsigned char *data, size_t datalen,
                s->ext.sech_session_key.data,                                   // unsigned char *out,
                32,                                       // size_t outlen,
                1                                        // int fatal
                )) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        rv = 0;
        goto err;
    }
    s->ext.sech_session_key.ready = 1;
    rv = 1;
err:
    EVP_MD_CTX_free(ctx);
    // EVP_MD_free(md);
    return rv;
}

int sech2_make_ClientHelloOuterContext_server(SSL_CONNECTION *s)
{
    size_t written = s->ext.sech_client_hello_transcript_for_confirmation_len;
    unsigned char * ch = s->ext.sech_client_hello_transcript_for_confirmation;
    const size_t session_id_len = s->tmp_session_id_len;
    return sech2_make_ClientHelloOuterContext(s, ch, written, session_id_len);
}

int sech2_make_ClientHelloOuterContext(SSL_CONNECTION *s, unsigned char * ch, size_t ch_len, size_t session_id_len) 
{
    OPENSSL_assert(session_id_len == 32); // TODO this is not strictly necessary?
    OPENSSL_assert(ch);
    OPENSSL_assert(ch_len);
    const size_t version_length = 2;
    const size_t header_length = 4;
    s->ext.sech_ClientHelloOuterContext = OPENSSL_memdup(ch, ch_len);

    if(s->ext.sech_ClientHelloOuterContext == NULL)
    { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return 0; }
    s->ext.sech_ClientHelloOuterContext_len = ch_len; 

    {
        void * random = s->ext.sech_ClientHelloOuterContext + header_length + version_length + OSSL_SECH2_AEAD_NONCE_LEN;
        char val = 0;
        char len = SSL3_RANDOM_SIZE - OSSL_SECH2_AEAD_NONCE_LEN; 
        // replace sech cipher text and tag with 0s
        memset(random, val, len);
    }
    {
        void * session_id_data_area = s->ext.sech_ClientHelloOuterContext + header_length + version_length + SSL3_RANDOM_SIZE + 1;
        char val = 0;
        // replace sech cipher text and tag with 0s
        memset(session_id_data_area, val, session_id_len);
    }
    return 1;
}

// int sech2_save_ClientHello2(SSL_CONNECTION *s, WPACKET *pkt) {
//     int rv = 0;
//     size_t written;
//     if(!WPACKET_get_total_written(pkt, &written)) {
//         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
//         return rv;
//     }
//     unsigned char * ch = WPACKET_get_curr(pkt) - written;
//     OPENSSL_assert(ch);
//     OPENSSL_assert(written);
//     s->ext.sech_ClientHello2 = OPENSSL_memdup(ch, written);
//     s->ext.sech_ClientHello2_len = written;
//     rv = 1;
//     return rv;
// }

int sech2_make_ClientHelloInner(SSL_CONNECTION *s)
{
    static size_t version_length = 2;
    static size_t header_length = 4;
    unsigned char * ch = s->ext.sech_client_hello_transcript_for_confirmation;
    size_t len = s->ext.sech_client_hello_transcript_for_confirmation_len;
    OPENSSL_assert(s->ext.sech_client_hello_transcript_for_confirmation);
    s->ext.sech_ClientHelloInner = OPENSSL_memdup(ch, len);
    if(s->ext.sech_ClientHelloInner == NULL)
    { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return 0; }
    s->ext.sech_ClientHelloInner_len = s->ext.sech_ClientHelloOuterContext_len;

    char cover1_len = SSL3_RANDOM_SIZE - OSSL_SECH2_AEAD_NONCE_LEN;
    {
        void * cover1_start = s->ext.sech_ClientHelloInner + header_length + version_length + OSSL_SECH2_AEAD_NONCE_LEN;
        memcpy(cover1_start, s->ext.sech_plain_text.data, cover1_len);
    }
    {
        void * cover2_start = s->ext.sech_ClientHelloInner + header_length + version_length + SSL3_RANDOM_SIZE + 1;
        char cover2_len = (*(char*)(cover2_start - 1)) - 16;
        OPENSSL_assert(cover2_len == 16); // TODO not strictly necessary?
        memcpy(cover2_start, s->ext.sech_plain_text.data + cover1_len, cover2_len);
    }
    // TODO: set SNI to all 0s
    return 1;
}

#endif//OPENSSL_NO_ECH
