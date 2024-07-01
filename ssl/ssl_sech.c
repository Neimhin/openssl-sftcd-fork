
#include <openssl/ech.h>
#include "ssl_local.h"
#include "ech_local.h"
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
