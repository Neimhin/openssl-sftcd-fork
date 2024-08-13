#include <openssl/ech.h>
#include <openssl/rand.h>
#include "internal/packet.h"
#include "ssl_local.h"
#include "ech_local.h"
#include "sech_local.h"
#ifndef OPENSSL_NO_SECH
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

/*
 * @brief info about a KEM
 * Used to store constants from Section 7.1 "Table 2 KEM IDs"
 * and the bitmask for EC curves described in Section 7.1.3 DeriveKeyPair
 */
typedef struct {
    uint16_t      kem_id; /* code point for key encipherment method */
    const char    *keytype; /* string form of algtype "EC"/"X25519"/"X448" */
    const char    *groupname; /* string form of EC group for NIST curves  */
    const char    *mdname; /* hash alg name for the HKDF */
    size_t        Nsecret; /* size of secrets */
    size_t        Nenc; /* length of encapsulated key */
    size_t        Npk; /* length of public key */
    size_t        Nsk; /* length of raw private key */
    uint8_t       bitmask;
} OSSL_HPKE_KEM_INFO;

/*
 * @brief info about a KDF
 */
typedef struct {
    uint16_t       kdf_id; /* code point for KDF */
    const char     *mdname; /* hash alg name for the HKDF */
    size_t         Nh; /* length of hash/extract output */
} OSSL_HPKE_KDF_INFO;

/*
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t       aead_id; /* code point for aead alg */
    const char     *name;   /* alg name */
    size_t         taglen; /* aead tag len */
    size_t         Nk; /* size of a key for this aead */
    size_t         Nn; /* length of a nonce for this aead */
} OSSL_HPKE_AEAD_INFO;
struct ossl_hpke_ctx_st
{
    OSSL_LIB_CTX *libctx; /* library context */
    char *propq; /* properties */
    int mode; /* HPKE mode */
    OSSL_HPKE_SUITE suite; /* suite */
    const OSSL_HPKE_KEM_INFO *kem_info;
    const OSSL_HPKE_KDF_INFO *kdf_info;
    const OSSL_HPKE_AEAD_INFO *aead_info;
    EVP_CIPHER *aead_ciph;
    int role; /* sender(0) or receiver(1) */
    uint64_t seq; /* aead sequence number */
    unsigned char *shared_secret; /* KEM output, zz */
    size_t shared_secretlen;
    unsigned char *key; /* final aead key */
    size_t keylen;
    unsigned char *nonce; /* aead base nonce */
    size_t noncelen;
    unsigned char *exportersec; /* exporter secret */
    size_t exporterseclen;
    char *pskid; /* PSK stuff */
    unsigned char *psk;
    size_t psklen;
    EVP_PKEY *authpriv; /* sender's authentication private key */
    unsigned char *authpub; /* auth public key */
    size_t authpublen;
    unsigned char *ikme; /* IKM for sender deterministic key gen */
    size_t ikmelen;
};

/*
 * The enc and payload are allocated here and must be freed by the caller
 * if encryption is successful.
 */
int sech5_hpke_enc(SSL *s,
        const struct sech5_hpke_enc_in in,
        struct sech5_hpke_enc_out * out
                   // unsigned char * clear, size_t clear_len,
                   // OSSL_HPKE_SUITE hpke_suite,
                   // unsigned char * pub, size_t pub_len,
                   // unsigned char * info,
                   // size_t info_len,
                   // const unsigned char * aad,
                   // size_t aad_len,
                   // unsigned char ** enc,
                   // size_t * enc_len,
                   // unsigned char ** ciphertext,
                   // size_t * ciphertext_len
                   )
{
    int rv = 1;
    unsigned char * mypub = NULL;
    OSSL_HPKE_CTX * hpke_ctx = NULL;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    int subrv = 0;
    size_t mypub_len = 0;
    unsigned char * cipher = NULL;
    size_t cipher_len = 0;
    size_t enc_len = 0;
    enc_len = OSSL_HPKE_get_public_encap_size(in.hpke_suite);
    mypub = OPENSSL_malloc(enc_len);
    if(mypub == NULL) {
        rv = 0;
        goto end;
    }
    hpke_ctx = OSSL_HPKE_CTX_new(
            hpke_mode, in.hpke_suite,
            OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if(hpke_ctx == NULL) {
        rv = 0;
    }

    mypub_len = enc_len;
    subrv = OSSL_HPKE_encap(
            hpke_ctx, mypub, &mypub_len,
            in.pub, in.pub_len, in.info, in.info_len);
    sech_debug_buffer("shared secret client", hpke_ctx->shared_secret, hpke_ctx->shared_secretlen);
    fprintf(stderr, "seq client%llu\n", hpke_ctx->seq);
    if(!subrv) {
        rv = 0;
        goto end;
    }
    cipher_len = OSSL_HPKE_get_ciphertext_size(in.hpke_suite, in.clear_len);
    cipher = OPENSSL_malloc(cipher_len);
    if(cipher == NULL) {
        rv = 0;
        goto end;
    }
    sech_debug_buffer("aad client", in.aad, in.aad_len);
    subrv = OSSL_HPKE_seal(hpke_ctx,
            cipher, &cipher_len,
            in.aad, in.aad_len,
            in.clear, in.clear_len);
    out->enc = mypub;
    out->enc_len = mypub_len;
    out->ciphertext =  cipher;
    out->ciphertext_len = cipher_len;
    fprintf(stderr, "cipher_len %lu\n", out->ciphertext_len);
    rv = 1;
end:
    if(rv != 1) {
        OPENSSL_free(mypub);
        OPENSSL_free(cipher);
    }
    return rv;
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
    case 0: // no sech
    case 2:
    case 5:
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

int sech2_make_payload64(SSL_CONNECTION *s, WPACKET * pkt) {
    SSL_CTX * sctx = SSL_CONNECTION_GET_CTX(s);
    unsigned char * tag = NULL;
    size_t tag_len = 16;
    size_t written;
    if(!WPACKET_get_total_written(pkt, &written)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    unsigned char * ch = WPACKET_get_curr(pkt) - written;
    unsigned char * iv = ch + 4 + 2;
    size_t iv_len = 12;
    s->ext.sech_inner_random = OPENSSL_malloc(OSSL_SECH2_INNER_RANDOM_LEN);
    unsigned char * key = s->ext.sech_session_key.data;
    size_t key_len = sizeof(s->ext.sech_session_key.data);
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

    fprintf(stderr, "cryptkey\n");
    BIO_dump_fp(stderr, key, key_len);
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
    s->ext.sech_plain_text.ready = 1;
    fprintf(stderr, "iv\n");
    BIO_dump_fp(stderr, iv, iv_len);
    fprintf(stderr, "ct client\n");
    BIO_dump_fp(stderr, s->ext.sech_cipher_text, s->ext.sech_cipher_text_len);
    fprintf(stderr, "tag client\n");
    BIO_dump_fp(stderr, tag, tag_len);
    // iv_len is fixed in protocol (no negotiation))
    OPENSSL_assert(iv_len == sizeof(s->ext.sech_aead_nonce.data));
    memcpy(s->ext.sech_aead_nonce.data, iv, iv_len);
    s->ext.sech_aead_tag.ready = 1;
    if((iv_len + s->ext.sech_cipher_text_len + tag_len)
            != (SSL3_RANDOM_SIZE + 32)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(s->ext.sech_payload64.data, iv, iv_len);
    memcpy(s->ext.sech_payload64.data + iv_len,
            s->ext.sech_cipher_text, s->ext.sech_cipher_text_len);
    memcpy(s->ext.sech_payload64.data + iv_len + s->ext.sech_cipher_text_len,
            tag, tag_len);
    s->ext.sech_payload64.ready = 1;
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
    unsigned char * session_id = p + 32 + 1;

    memcpy(p, s->ext.sech_payload64.data, 32);
    memcpy(session_id, s->ext.sech_payload64.data + 32, 32);
    memcpy(s->tmp_session_id, session_id, 32);

    s->ext.sech_client_hello_transcript_for_confirmation = OPENSSL_memdup(ch, written);
    s->ext.sech_client_hello_transcript_for_confirmation_len = written;
    OPENSSL_assert((written >> 24) == 0); // assert length fits in uint24
    // TODO: use WPACKET_fill_lengths
    unsigned char * length_field = s->ext.sech_client_hello_transcript_for_confirmation + 1;
    size_t len = written - 4;
    length_field[0] = (len >> 16) & 0xFF; // Most significant byte
    length_field[1] = (len >> 8) & 0xFF;  // Middle byte
    length_field[2] = len & 0xFF;         // Least significant byte55);
    return 1;
}

int sech2_make_ClientHelloOuterContext_client(SSL_CONNECTION *s, WPACKET *pkt, int sech_version)
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
    int rv = sech2_make_ClientHelloOuterContext(s, ch, written, session_id_len, sech_version);
    sech_debug_buffer("ch client", ch, written);
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
    fprintf(stderr, "session key in [server=%i] %p\n", s->server, s);
    BIO_dump_fp(stderr, s->ext.sech_ClientHelloOuterContext, s->ext.sech_ClientHelloOuterContext_len);
    BIO_dump_fp(stderr, s->ext.sech_symmetric_key, s->ext.sech_symmetric_key_len);
    BIO_dump_fp(stderr, hash, hash_len);
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
    BIO_dump_fp(stderr, s->ext.sech_session_key.data, 32);
    s->ext.sech_session_key.ready = 1;
    rv = 1;
err:
    EVP_MD_CTX_free(ctx);
    // EVP_MD_free(md);
    return rv;
}

int sech2_make_ClientHelloOuterContext_server(SSL_CONNECTION *s, int sech_version)
{
    size_t written = s->ext.sech_client_hello_transcript_for_confirmation_len;
    unsigned char * ch = s->ext.sech_client_hello_transcript_for_confirmation;
    const size_t session_id_len = s->tmp_session_id_len;
    return sech2_make_ClientHelloOuterContext(s, ch, written, session_id_len, sech_version);
}

int sech2_make_ClientHelloOuterContext(SSL_CONNECTION *s, unsigned char * ch, size_t ch_len, size_t session_id_len, int sech_version) 
{
    OPENSSL_assert(session_id_len == 32);
    OPENSSL_assert(ch);
    OPENSSL_assert(ch_len);
    const size_t version_length = 2;
    const size_t header_length = 4;
    size_t len = ch_len;
    if(s->ext.sech_binderoffset >= 0) {
        len = s->ext.sech_binderoffset;
    }
    s->ext.sech_ClientHelloOuterContext = OPENSSL_memdup(ch, len);

    if(s->ext.sech_ClientHelloOuterContext == NULL)
    { SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR); return 0; }
    s->ext.sech_ClientHelloOuterContext_len = len; 

    if(sech_version == 2)
    {
        void * random = s->ext.sech_ClientHelloOuterContext + header_length + version_length + OSSL_SECH2_AEAD_NONCE_LEN;
        char val = 0;
        char len = SSL3_RANDOM_SIZE - OSSL_SECH2_AEAD_NONCE_LEN; 
        // replace sech cipher text and tag with 0s
        memset(random, val, len);
    }
    else if (sech_version == 5){
        void * random = s->ext.sech_ClientHelloOuterContext + header_length + version_length;
        char val = 0;
        char len = SSL3_RANDOM_SIZE; 
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

int sech5_make_ClientHelloInner(SSL_CONNECTION *s)
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

    char cover1_len = 16;
    {
        void * cover1_start = s->ext.sech_ClientHelloInner + header_length + version_length + SSL3_RANDOM_SIZE + 1;
        memcpy(cover1_start, s->ext.sech_plain_text.data, cover1_len);
    }
    // TODO: set SNI to all 0s
    return 1;
}

int sech2_client(SSL_CONNECTION * s, WPACKET * pkt) {
    switch(s->ext.sech_version) {
        case 2:
            if(s->ext.sech_symmetric_key == NULL ||
                s->ext.ech.ch_depth != OSSL_ECH_OUTER_CH_TYPE)
                return 1;
            if(s->ext.sech_hrr == NULL) {
                sech2_make_ClientHelloOuterContext_client(s, pkt, 2);
                sech2_derive_session_key(s);
                fprintf(stderr, "ClientHelloOuterContext client\n");
                BIO_dump_fp(stderr,
                        s->ext.sech_ClientHelloOuterContext,
                        s->ext.sech_ClientHelloOuterContext_len);
                fprintf(stderr, "sech session key client\n");
                BIO_dump_fp(stderr, s->ext.sech_session_key.data, 32);
                if(sech2_make_payload64(s, pkt) != 1) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                sech2_edit_client_hello(s, pkt);
                sech2_make_ClientHelloInner(s);
                sech2_init_finished_mac(s);
                sech2_finish_mac(s, s->ext.sech_ClientHelloInner, s->ext.sech_ClientHelloInner_len);
                return 1;
            } else if( s->ext.sech_hrr && (
                !sech2_make_ClientHello2_client(s, pkt) ||
                !sech2_finish_mac(s,
                    s->ext.sech_ClientHello2,
                    s->ext.sech_ClientHello2_len))) {
                    return 0;
            }
        case 5:
            if(s->ext.sech_configs == NULL)
                return 1;
            if(s->ext.sech_hrr == NULL) {
                sech2_make_ClientHelloOuterContext_client(s, pkt, 5);
                ECHConfig * sechcfg = s->ext.sech_configs->cfg->recs;
                OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
                hpke_suite.kem_id = sechcfg->kem_id;
                unsigned char clear[16] = {0};
                memcpy(clear, s->ext.sech_inner_servername,
                        s->ext.sech_inner_servername_len);
                {
                    struct sech5_hpke_enc_out hpke_out = { 0 };
                    struct sech5_hpke_enc_in in = {
                        .clear = clear,
                        .clear_len = 16,
                        .hpke_suite = hpke_suite,
                        .pub = sechcfg->pub,
                        .pub_len = sechcfg->pub_len,
                        .info = "sech5",
                        .info_len = sizeof("sech5"),
                        .aad = s->ext.sech_ClientHelloOuterContext,
                        .aad_len = s->ext.sech_ClientHelloOuterContext_len,
                    };
                    if(!sech5_hpke_enc(s, in, &hpke_out)) {
                        return 0;
                    }
                    sech_debug_buffer("hpke enc",
                            hpke_out.enc, hpke_out.enc_len);
                    sech_debug_buffer("hpke cipher",
                            hpke_out.ciphertext, hpke_out.ciphertext_len);
                    OPENSSL_assert(hpke_out.enc_len == 32);
                    OPENSSL_assert(hpke_out.ciphertext_len == 32);
                    memcpy(s->ext.sech_payload64.data, hpke_out.enc, hpke_out.enc_len);
                    memcpy(s->ext.sech_payload64.data+hpke_out.enc_len, hpke_out.ciphertext, hpke_out.ciphertext_len);
                    s->ext.sech_payload64.ready = 1;
                    sech2_edit_client_hello(s, pkt);
                    sech5_make_ClientHelloInner(s);
                    sech_debug_buffer("CHI client", s->ext.sech_ClientHelloInner, s->ext.sech_ClientHelloInner_len);
                    sech2_init_finished_mac(s);
                    sech2_finish_mac(s, s->ext.sech_ClientHelloInner, s->ext.sech_ClientHelloInner_len);
                }

                return 1;
            }
            return 0;
        default:
            return 1;
    }
}
#endif//OPENSSL_NO_SECH
