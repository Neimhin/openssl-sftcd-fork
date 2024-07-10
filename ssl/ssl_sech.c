
#include <openssl/ech.h>
#include <openssl/rand.h>
#include "ssl_local.h"
#include "ech_local.h"
#ifndef OPENSSL_NO_ECH
#include <openssl/sech.h>

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
        ctx->ext.sech_version = version;
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

int SSL_CTX_set_sech_inner_servername(SSL_CTX *ctx, char* inner_servername, int inner_servername_len)
{
    if(inner_servername_len == 0 && inner_servername != NULL) {
      inner_servername_len = strlen(inner_servername);
    }
    ctx->ext.sech_inner_servername_len = inner_servername_len;
    ctx->ext.sech_inner_servername = OPENSSL_strdup(inner_servername);
    return 1;
}

void sech2_edit_client_hello(SSL_CONNECTION *s, WPACKET *pkt) {
    const size_t version_length = 2;
    const size_t session_id_len = 32;
    size_t written;
    if(!WPACKET_get_total_written(pkt, &written)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return CON_FUNC_ERROR;
    }
    unsigned char * ch = WPACKET_get_curr(pkt) - written;
    unsigned char * p = ch + 4 + 2;
    unsigned char * iv = NULL;
    unsigned char * tag = NULL;
    size_t tag_len = 16;
    size_t iv_len = 0;
    s->ext.sech_inner_random = OPENSSL_malloc(OSSL_SECH2_INNER_RANDOM_LEN);
    unsigned char * key = s->ext.sech_symmetric_key;
    size_t key_len = s->ext.sech_symmetric_key_len;
    SSL_CTX *sctx = SSL_CONNECTION_GET_CTX(s);
    if(RAND_bytes_ex(sctx->libctx, s->ext.sech_inner_random, OSSL_SECH2_INNER_RANDOM_LEN, RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return CON_FUNC_ERROR;
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
        return CON_FUNC_ERROR;
    }
    else {
      s->ext.sech_plain_text.ready = 1;
      OPENSSL_assert(iv_len == sizeof(s->ext.sech_aead_nonce.data)); // iv_len is fixed in protocol (no negotiation))
      memcpy(s->ext.sech_aead_nonce.data, iv, iv_len);
      if((iv_len + s->ext.sech_cipher_text_len + tag_len) != (SSL3_RANDOM_SIZE + 32))
      { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return CON_FUNC_ERROR; }

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
      s->ext.sech_client_hello_transcript_for_confirmation = OPENSSL_memdup(ch + 4, written - 4);
      s->ext.sech_client_hello_transcript_for_confirmation_len = written - 4;
      if(!sech2_make_ClientHelloOuterContext(s))
      { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return CON_FUNC_ERROR; }
      // s->ext.sech_ClientHelloOuterContext = OPENSSL_memdup(
      //         s->ext.sech_client_hello_transcript_for_confirmation,
      //         s->ext.sech_client_hello_transcript_for_confirmation_len);
      // s->ext.sech_ClientHelloOuterContext_len = s->ext.sech_client_hello_transcript_for_confirmation_len;
      // {
      //     void * dst = s->ext.sech_ClientHelloOuterContext + version_length + OSSL_SECH2_AEAD_NONCE_LEN;
      //     char val = 0;
      //     char len = SSL3_RANDOM_SIZE + session_id_len - OSSL_SECH2_AEAD_NONCE_LEN;
      //     // replace sech cipher text and tag with 0s
      //     memset(dst, val, len);
      // }
      OPENSSL_free(iv);
    }
}

int sech2_make_ClientHelloOuterContext(SSL_CONNECTION *s)
{
    const size_t session_id_len = s->tmp_session_id_len;
    const size_t version_length = 2;
    OPENSSL_assert(session_id_len == 32);
    OPENSSL_assert(s->ext.sech_client_hello_transcript_for_confirmation);
    OPENSSL_assert(s->ext.sech_client_hello_transcript_for_confirmation_len);
    s->ext.sech_ClientHelloOuterContext = OPENSSL_memdup(
            s->ext.sech_client_hello_transcript_for_confirmation,
            s->ext.sech_client_hello_transcript_for_confirmation_len);
    s->ext.sech_ClientHelloOuterContext_len = s->ext.sech_client_hello_transcript_for_confirmation_len;
    {
        void * dst = s->ext.sech_ClientHelloOuterContext + version_length + OSSL_SECH2_AEAD_NONCE_LEN;
        char val = 0;
        char len = SSL3_RANDOM_SIZE + session_id_len - OSSL_SECH2_AEAD_NONCE_LEN;
        // replace sech cipher text and tag with 0s
        memset(dst, val, len);
    }
    return 1;
}
#endif//OPENSSL_NO_ECH
