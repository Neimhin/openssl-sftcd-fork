/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>
#include "../ssl_local.h"
#include "statem_local.h"
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_ESNI
#include <openssl/rand.h>
#include <openssl/trace.h>
/* for sockaddr stuff - not portable!!!  */
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
/* for timing in TRACE */
#include <time.h>
#endif

#define COOKIE_STATE_FORMAT_VERSION     0

/*
 * 2 bytes for packet length, 2 bytes for format version, 2 bytes for
 * protocol version, 2 bytes for group id, 2 bytes for cipher id, 1 byte for
 * key_share present flag, 4 bytes for timestamp, 2 bytes for the hashlen,
 * EVP_MAX_MD_SIZE for transcript hash, 1 byte for app cookie length, app cookie
 * length bytes, SHA256_DIGEST_LENGTH bytes for the HMAC of the whole thing.
 */
#define MAX_COOKIE_SIZE (2 + 2 + 2 + 2 + 2 + 1 + 4 + 2 + EVP_MAX_MD_SIZE + 1 \
                         + SSL_COOKIE_LENGTH + SHA256_DIGEST_LENGTH)

/*
 * Message header + 2 bytes for protocol version + number of random bytes +
 * + 1 byte for legacy session id length + number of bytes in legacy session id
 * + 2 bytes for ciphersuite + 1 byte for legacy compression
 * + 2 bytes for extension block length + 6 bytes for key_share extension
 * + 4 bytes for cookie extension header + the number of bytes in the cookie
 */
#define MAX_HRR_SIZE    (SSL3_HM_HEADER_LENGTH + 2 + SSL3_RANDOM_SIZE + 1 \
                         + SSL_MAX_SSL_SESSION_ID_LENGTH + 2 + 1 + 2 + 6 + 4 \
                         + MAX_COOKIE_SIZE)

#ifndef OPENSSL_NO_ESNI
/*
 * Max ESNI ciphertext is max DNSNAME (255)+TLS SNI encoding(5) + nonce (16) + GCM tag (16)
 */
#define MAX_ESNI_CIPHER_SIZE (255+5+16+EVP_GCM_TLS_TAG_LEN)
#endif

/*
 * Parse the client's renegotiation binding and abort if it's not right
 */
int tls_parse_ctos_renegotiate(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    unsigned int ilen;
    const unsigned char *data;

    /* Parse the length byte */
    if (!PACKET_get_1(pkt, &ilen)
        || !PACKET_get_bytes(pkt, &data, ilen)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
                 SSL_R_RENEGOTIATION_ENCODING_ERR);
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != s->s3.previous_client_finished_len) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
                 SSL_R_RENEGOTIATION_MISMATCH);
        return 0;
    }

    if (memcmp(data, s->s3.previous_client_finished,
               s->s3.previous_client_finished_len)) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PARSE_CTOS_RENEGOTIATE,
                 SSL_R_RENEGOTIATION_MISMATCH);
        return 0;
    }

    s->s3.send_connection_binding = 1;

    return 1;
}

/*-
 * The servername extension is treated as follows:
 *
 * - Only the hostname type is supported with a maximum length of 255.
 * - The servername is rejected if too long or if it contains zeros,
 *   in which case an fatal alert is generated.
 * - The servername field is maintained together with the session cache.
 * - When a session is resumed, the servername call back invoked in order
 *   to allow the application to position itself to the right context.
 * - The servername is acknowledged if it is new for a session or when
 *   it is identical to a previously used for the same session.
 *   Applications can control the behaviour.  They can at any time
 *   set a 'desirable' servername for a new SSL object. This can be the
 *   case for example with HTTPS when a Host: header field is received and
 *   a renegotiation is requested. In this case, a possible servername
 *   presented in the new client hello is only acknowledged if it matches
 *   the value of the Host: field.
 * - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
 *   if they provide for changing an explicit servername context for the
 *   session, i.e. when the session has been established with a servername
 *   extension.
 * - On session reconnect, the servername extension may be absent.
 */
int tls_parse_ctos_server_name(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    unsigned int servname_type;
    PACKET sni, hostname;

    if (!PACKET_as_length_prefixed_2(pkt, &sni)
        /* ServerNameList must be at least 1 byte long. */
        || PACKET_remaining(&sni) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_SERVER_NAME,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * Although the intent was for server_name to be extensible, RFC 4366
     * was not clear about it; and so OpenSSL among other implementations,
     * always and only allows a 'host_name' name types.
     * RFC 6066 corrected the mistake but adding new name types
     * is nevertheless no longer feasible, so act as if no other
     * SNI types can exist, to simplify parsing.
     *
     * Also note that the RFC permits only one SNI value per type,
     * i.e., we can only have a single hostname.
     */
    if (!PACKET_get_1(&sni, &servname_type)
        || servname_type != TLSEXT_NAMETYPE_host_name
        || !PACKET_as_length_prefixed_2(&sni, &hostname)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_SERVER_NAME,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * In TLSv1.2 and below the SNI is associated with the session. In TLSv1.3
     * we always use the SNI value from the handshake.
     */
    if (!s->hit || SSL_IS_TLS13(s)) {
        if (PACKET_remaining(&hostname) > TLSEXT_MAXLEN_host_name) {
            SSLfatal(s, SSL_AD_UNRECOGNIZED_NAME,
                     SSL_F_TLS_PARSE_CTOS_SERVER_NAME,
                     SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (PACKET_contains_zero_byte(&hostname)) {
            SSLfatal(s, SSL_AD_UNRECOGNIZED_NAME,
                     SSL_F_TLS_PARSE_CTOS_SERVER_NAME,
                     SSL_R_BAD_EXTENSION);
            return 0;
        }

        /*
         * Store the requested SNI in the SSL as temporary storage.
         * If we accept it, it will get stored in the SSL_SESSION as well.
         */
        OPENSSL_free(s->ext.hostname);
        s->ext.hostname = NULL;
        if (!PACKET_strndup(&hostname, &s->ext.hostname)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_SERVER_NAME,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        s->servername_done = 1;
    } else {
        /*
         * In TLSv1.2 and below we should check if the SNI is consistent between
         * the initial handshake and the resumption. In TLSv1.3 SNI is not
         * associated with the session.
         */
        /*
         * TODO(openssl-team): if the SNI doesn't match, we MUST
         * fall back to a full handshake.
         */
        s->servername_done = (s->session->ext.hostname != NULL)
            && PACKET_equal(&hostname, s->session->ext.hostname,
                            strlen(s->session->ext.hostname));
    }

    return 1;
}

int tls_parse_ctos_maxfragmentlen(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    unsigned int value;

    if (PACKET_remaining(pkt) != 1 || !PACKET_get_1(pkt, &value)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_MAXFRAGMENTLEN,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Received |value| should be a valid max-fragment-length code. */
    if (!IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PARSE_CTOS_MAXFRAGMENTLEN,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * RFC 6066:  The negotiated length applies for the duration of the session
     * including session resumptions.
     * We should receive the same code as in resumed session !
     */
    if (s->hit && s->session->ext.max_fragment_len_mode != value) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PARSE_CTOS_MAXFRAGMENTLEN,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * Store it in session, so it'll become binding for us
     * and we'll include it in a next Server Hello.
     */
    s->session->ext.max_fragment_len_mode = value;
    return 1;
}

#ifndef OPENSSL_NO_SRP
int tls_parse_ctos_srp(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    PACKET srp_I;

    if (!PACKET_as_length_prefixed_1(pkt, &srp_I)
            || PACKET_contains_zero_byte(&srp_I)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SRP,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * TODO(openssl-team): currently, we re-authenticate the user
     * upon resumption. Instead, we MUST ignore the login.
     */
    if (!PACKET_strndup(&srp_I, &s->srp_ctx.login)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_SRP,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_EC
int tls_parse_ctos_ec_pt_formats(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    PACKET ec_point_format_list;

    if (!PACKET_as_length_prefixed_1(pkt, &ec_point_format_list)
        || PACKET_remaining(&ec_point_format_list) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_EC_PT_FORMATS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit) {
        if (!PACKET_memdup(&ec_point_format_list,
                           &s->ext.peer_ecpointformats,
                           &s->ext.peer_ecpointformats_len)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PARSE_CTOS_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}
#endif                          /* OPENSSL_NO_EC */

int tls_parse_ctos_session_ticket(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ext.session_ticket_cb &&
            !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ext.session_ticket_cb_arg)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_parse_ctos_sig_algs_cert(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    PACKET supported_sig_algs;

    if (!PACKET_as_length_prefixed_2(pkt, &supported_sig_algs)
            || PACKET_remaining(&supported_sig_algs) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SIG_ALGS_CERT, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit && !tls1_save_sigalgs(s, &supported_sig_algs, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SIG_ALGS_CERT, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

int tls_parse_ctos_sig_algs(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    PACKET supported_sig_algs;

    if (!PACKET_as_length_prefixed_2(pkt, &supported_sig_algs)
            || PACKET_remaining(&supported_sig_algs) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SIG_ALGS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit && !tls1_save_sigalgs(s, &supported_sig_algs, 0)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SIG_ALGS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_parse_ctos_status_request(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    PACKET responder_id_list, exts;

    /* We ignore this in a resumption handshake */
    if (s->hit)
        return 1;

    /* Not defined if we get one of these in a client Certificate */
    if (x != NULL)
        return 1;

    if (!PACKET_get_1(pkt, (unsigned int *)&s->ext.status_type)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        /*
         * We don't know what to do with any other type so ignore it.
         */
        s->ext.status_type = TLSEXT_STATUSTYPE_nothing;
        return 1;
    }

    if (!PACKET_get_length_prefixed_2 (pkt, &responder_id_list)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * We remove any OCSP_RESPIDs from a previous handshake
     * to prevent unbounded memory growth - CVE-2016-6304
     */
    sk_OCSP_RESPID_pop_free(s->ext.ocsp.ids, OCSP_RESPID_free);
    if (PACKET_remaining(&responder_id_list) > 0) {
        s->ext.ocsp.ids = sk_OCSP_RESPID_new_null();
        if (s->ext.ocsp.ids == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        s->ext.ocsp.ids = NULL;
    }

    while (PACKET_remaining(&responder_id_list) > 0) {
        OCSP_RESPID *id;
        PACKET responder_id;
        const unsigned char *id_data;

        if (!PACKET_get_length_prefixed_2(&responder_id_list, &responder_id)
                || PACKET_remaining(&responder_id) == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        id_data = PACKET_data(&responder_id);
        /* TODO(size_t): Convert d2i_* to size_t */
        id = d2i_OCSP_RESPID(NULL, &id_data,
                             (int)PACKET_remaining(&responder_id));
        if (id == NULL) {
            SSLfatal(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (id_data != PACKET_end(&responder_id)) {
            OCSP_RESPID_free(id);
            SSLfatal(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);

            return 0;
        }

        if (!sk_OCSP_RESPID_push(s->ext.ocsp.ids, id)) {
            OCSP_RESPID_free(id);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);

            return 0;
        }
    }

    /* Read in request_extensions */
    if (!PACKET_as_length_prefixed_2(pkt, &exts)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (PACKET_remaining(&exts) > 0) {
        const unsigned char *ext_data = PACKET_data(&exts);

        sk_X509_EXTENSION_pop_free(s->ext.ocsp.exts,
                                   X509_EXTENSION_free);
        s->ext.ocsp.exts =
            d2i_X509_EXTENSIONS(NULL, &ext_data, (int)PACKET_remaining(&exts));
        if (s->ext.ocsp.exts == NULL || ext_data != PACKET_end(&exts)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PARSE_CTOS_STATUS_REQUEST, SSL_R_BAD_EXTENSION);
            return 0;
        }
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_parse_ctos_npn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /*
     * We shouldn't accept this extension on a
     * renegotiation.
     */
    if (SSL_IS_FIRST_HANDSHAKE(s))
        s->s3.npn_seen = 1;

    return 1;
}
#endif

/*
 * Save the ALPN extension in a ClientHello.|pkt| holds the contents of the ALPN
 * extension, not including type and length. Returns: 1 on success, 0 on error.
 */
int tls_parse_ctos_alpn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx)
{
    PACKET protocol_list, save_protocol_list, protocol;

    if (!SSL_IS_FIRST_HANDSHAKE(s))
        return 1;

    if (!PACKET_as_length_prefixed_2(pkt, &protocol_list)
        || PACKET_remaining(&protocol_list) < 2) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ALPN,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    save_protocol_list = protocol_list;
    do {
        /* Protocol names can't be empty. */
        if (!PACKET_get_length_prefixed_1(&protocol_list, &protocol)
                || PACKET_remaining(&protocol) == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ALPN,
                     SSL_R_BAD_EXTENSION);
            return 0;
        }
    } while (PACKET_remaining(&protocol_list) != 0);

    OPENSSL_free(s->s3.alpn_proposed);
    s->s3.alpn_proposed = NULL;
    s->s3.alpn_proposed_len = 0;
    if (!PACKET_memdup(&save_protocol_list,
                       &s->s3.alpn_proposed, &s->s3.alpn_proposed_len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_ALPN,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_parse_ctos_use_srtp(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *srvr;
    unsigned int ct, mki_len, id;
    int i, srtp_pref;
    PACKET subpkt;

    /* Ignore this if we have no SRTP profiles */
    if (SSL_get_srtp_profiles(s) == NULL)
        return 1;

    /* Pull off the length of the cipher suite list  and check it is even */
    if (!PACKET_get_net_2(pkt, &ct) || (ct & 1) != 0
            || !PACKET_get_sub_packet(pkt, &subpkt, ct)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    srvr = SSL_get_srtp_profiles(s);
    s->srtp_profile = NULL;
    /* Search all profiles for a match initially */
    srtp_pref = sk_SRTP_PROTECTION_PROFILE_num(srvr);

    while (PACKET_remaining(&subpkt)) {
        if (!PACKET_get_net_2(&subpkt, &id)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_USE_SRTP,
                     SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
            return 0;
        }

        /*
         * Only look for match in profiles of higher preference than
         * current match.
         * If no profiles have been have been configured then this
         * does nothing.
         */
        for (i = 0; i < srtp_pref; i++) {
            SRTP_PROTECTION_PROFILE *sprof =
                sk_SRTP_PROTECTION_PROFILE_value(srvr, i);

            if (sprof->id == id) {
                s->srtp_profile = sprof;
                srtp_pref = i;
                break;
            }
        }
    }

    /* Now extract the MKI value as a sanity check, but discard it for now */
    if (!PACKET_get_1(pkt, &mki_len)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_USE_SRTP,
                 SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    if (!PACKET_forward(pkt, mki_len)
        || PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_USE_SRTP,
                 SSL_R_BAD_SRTP_MKI_VALUE);
        return 0;
    }

    return 1;
}
#endif

int tls_parse_ctos_etm(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    if (!(s->options & SSL_OP_NO_ENCRYPT_THEN_MAC))
        s->ext.use_etm = 1;

    return 1;
}

/*
 * Process a psk_kex_modes extension received in the ClientHello. |pkt| contains
 * the raw PACKET data for the extension. Returns 1 on success or 0 on failure.
 */
int tls_parse_ctos_psk_kex_modes(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3
    PACKET psk_kex_modes;
    unsigned int mode;

    if (!PACKET_as_length_prefixed_1(pkt, &psk_kex_modes)
            || PACKET_remaining(&psk_kex_modes) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_PSK_KEX_MODES,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    while (PACKET_get_1(&psk_kex_modes, &mode)) {
        if (mode == TLSEXT_KEX_MODE_KE_DHE)
            s->ext.psk_kex_mode |= TLSEXT_KEX_MODE_FLAG_KE_DHE;
        else if (mode == TLSEXT_KEX_MODE_KE
                && (s->options & SSL_OP_ALLOW_NO_DHE_KEX) != 0)
            s->ext.psk_kex_mode |= TLSEXT_KEX_MODE_FLAG_KE;
    }
#endif

    return 1;
}

/*
 * Process a key_share extension received in the ClientHello. |pkt| contains
 * the raw PACKET data for the extension. Returns 1 on success or 0 on failure.
 */
int tls_parse_ctos_key_share(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                             size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned int group_id;
    PACKET key_share_list, encoded_pt;
    const uint16_t *clntgroups, *srvrgroups;
    size_t clnt_num_groups, srvr_num_groups;
    int found = 0;

    if (s->hit && (s->ext.psk_kex_mode & TLSEXT_KEX_MODE_FLAG_KE_DHE) == 0)
        return 1;

#ifndef OPENSSL_NO_ECH
    /* 
     * Sanity check - different for outer & inner CH 
     * We expect peer_temp to be NULL 1st time and not NULL 2nd time
     */
    if (s->ext.ch_depth==0) {
        /*
         * outer CH
         */
        if (s->s3.peer_tmp != NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else if (s->ext.ch_depth==1) {
        /*
         * inner CH
         */
        if ( s->s3.peer_tmp != NULL) {
            /* 
             * This is the nominal case, but we now set it to NULL for
             * 2nd key derivation
             */
            s->s3.peer_tmp=NULL;
        } else if (s->s3.peer_tmp == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
#else
    /* Sanity check */
    if (s->s3.peer_tmp != NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif

#ifndef OPENSSL_NO_ESNI
    /*
     * We want to recored the encoded key share(s) for later use
     * as AAD in ESNI
     */
    const unsigned char *kse=PACKET_data(pkt);
    const size_t kse_len=PACKET_remaining(pkt);
    if (s->ext.kse!=NULL) {
        OPENSSL_free(s->ext.kse);
        s->ext.kse=NULL;
        s->ext.kse_len=0;
    }
    s->ext.kse=OPENSSL_malloc(kse_len);
    if (s->ext.kse==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    s->ext.kse_len=kse_len;
    memcpy(s->ext.kse,kse,kse_len);
#endif

    if (!PACKET_as_length_prefixed_2(pkt, &key_share_list)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    /* Get our list of supported groups */
    tls1_get_supported_groups(s, &srvrgroups, &srvr_num_groups);
    /* Get the clients list of supported groups. */
    tls1_get_peer_groups(s, &clntgroups, &clnt_num_groups);
    if (clnt_num_groups == 0) {
        /*
         * This can only happen if the supported_groups extension was not sent,
         * because we verify that the length is non-zero when we process that
         * extension.
         */
        SSLfatal(s, SSL_AD_MISSING_EXTENSION, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION);
        return 0;
    }

    if (s->s3.group_id != 0 && PACKET_remaining(&key_share_list) == 0) {
        /*
         * If we set a group_id already, then we must have sent an HRR
         * requesting a new key_share. If we haven't got one then that is an
         * error
         */
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                 SSL_R_BAD_KEY_SHARE);
        return 0;
    }

    while (PACKET_remaining(&key_share_list) > 0) {
        if (!PACKET_get_net_2(&key_share_list, &group_id)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                     SSL_R_LENGTH_MISMATCH);
            return 0;
        }

        /*
         * If we already found a suitable key_share we loop through the
         * rest to verify the structure, but don't process them.
         */
        if (found)
            continue;

        /*
         * If we sent an HRR then the key_share sent back MUST be for the group
         * we requested, and must be the only key_share sent.
         */
        if (s->s3.group_id != 0
                && (group_id != s->s3.group_id
                    || PACKET_remaining(&key_share_list) != 0)) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Check if this share is in supported_groups sent from client */
        if (!check_in_list(s, group_id, clntgroups, clnt_num_groups, 0)) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Check if this share is for a group we can use */
        if (!check_in_list(s, group_id, srvrgroups, srvr_num_groups, 1)) {
            /* Share not suitable */
            continue;
        }

        if ((s->s3.peer_tmp = ssl_generate_param_group(s, group_id)) == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_KEY_SHARE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            return 0;
        }

        s->s3.group_id = group_id;

        if (!EVP_PKEY_set1_tls_encodedpoint(s->s3.peer_tmp,
                PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PARSE_CTOS_KEY_SHARE, SSL_R_BAD_ECPOINT);
            return 0;
        }

        found = 1;
    }
#endif

    return 1;
}

int tls_parse_ctos_cookie(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                          size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned int format, version, key_share, group_id;
    EVP_MD_CTX *hctx;
    EVP_PKEY *pkey;
    PACKET cookie, raw, chhash, appcookie;
    WPACKET hrrpkt;
    const unsigned char *data, *mdin, *ciphdata;
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    unsigned char hrr[MAX_HRR_SIZE];
    size_t rawlen, hmaclen, hrrlen, ciphlen;
    unsigned long tm, now;

    /* Ignore any cookie if we're not set up to verify it */
    if (s->ctx->verify_stateless_cookie_cb == NULL
            || (s->s3.flags & TLS1_FLAGS_STATELESS) == 0)
        return 1;

    if (!PACKET_as_length_prefixed_2(pkt, &cookie)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    raw = cookie;
    data = PACKET_data(&raw);
    rawlen = PACKET_remaining(&raw);
    if (rawlen < SHA256_DIGEST_LENGTH
            || !PACKET_forward(&raw, rawlen - SHA256_DIGEST_LENGTH)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    mdin = PACKET_data(&raw);

    /* Verify the HMAC of the cookie */
    hctx = EVP_MD_CTX_create();
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                        s->session_ctx->ext.cookie_hmac_key,
                                        sizeof(s->session_ctx->ext
                                               .cookie_hmac_key));
    if (hctx == NULL || pkey == NULL) {
        EVP_MD_CTX_free(hctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    hmaclen = SHA256_DIGEST_LENGTH;
    if (EVP_DigestSignInit(hctx, NULL, EVP_sha256(), NULL, pkey) <= 0
            || EVP_DigestSign(hctx, hmac, &hmaclen, data,
                              rawlen - SHA256_DIGEST_LENGTH) <= 0
            || hmaclen != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(hctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    EVP_MD_CTX_free(hctx);
    EVP_PKEY_free(pkey);

    if (CRYPTO_memcmp(hmac, mdin, SHA256_DIGEST_LENGTH) != 0) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_COOKIE_MISMATCH);
        return 0;
    }

    if (!PACKET_get_net_2(&cookie, &format)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    /* Check the cookie format is something we recognise. Ignore it if not */
    if (format != COOKIE_STATE_FORMAT_VERSION)
        return 1;

    /*
     * The rest of these checks really shouldn't fail since we have verified the
     * HMAC above.
     */

    /* Check the version number is sane */
    if (!PACKET_get_net_2(&cookie, &version)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    if (version != TLS1_3_VERSION) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_BAD_PROTOCOL_VERSION_NUMBER);
        return 0;
    }

    if (!PACKET_get_net_2(&cookie, &group_id)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    ciphdata = PACKET_data(&cookie);
    if (!PACKET_forward(&cookie, 2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    if (group_id != s->s3.group_id
            || s->s3.tmp.new_cipher
               != ssl_get_cipher_by_char(s, ciphdata, 0)) {
        /*
         * We chose a different cipher or group id this time around to what is
         * in the cookie. Something must have changed.
         */
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_BAD_CIPHER);
        return 0;
    }

    if (!PACKET_get_1(&cookie, &key_share)
            || !PACKET_get_net_4(&cookie, &tm)
            || !PACKET_get_length_prefixed_2(&cookie, &chhash)
            || !PACKET_get_length_prefixed_1(&cookie, &appcookie)
            || PACKET_remaining(&cookie) != SHA256_DIGEST_LENGTH) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    /* We tolerate a cookie age of up to 10 minutes (= 60 * 10 seconds) */
    now = (unsigned long)time(NULL);
    if (tm > now || (now - tm) > 600) {
        /* Cookie is stale. Ignore it */
        return 1;
    }

    /* Verify the app cookie */
    if (s->ctx->verify_stateless_cookie_cb(s, PACKET_data(&appcookie),
                                     PACKET_remaining(&appcookie)) == 0) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 SSL_R_COOKIE_MISMATCH);
        return 0;
    }

    /*
     * Reconstruct the HRR that we would have sent in response to the original
     * ClientHello so we can add it to the transcript hash.
     * Note: This won't work with custom HRR extensions
     */
    if (!WPACKET_init_static_len(&hrrpkt, hrr, sizeof(hrr), 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_put_bytes_u8(&hrrpkt, SSL3_MT_SERVER_HELLO)
            || !WPACKET_start_sub_packet_u24(&hrrpkt)
            || !WPACKET_put_bytes_u16(&hrrpkt, TLS1_2_VERSION)
            || !WPACKET_memcpy(&hrrpkt, hrrrandom, SSL3_RANDOM_SIZE)
            || !WPACKET_sub_memcpy_u8(&hrrpkt, s->tmp_session_id,
                                      s->tmp_session_id_len)
            || !s->method->put_cipher_by_char(s->s3.tmp.new_cipher, &hrrpkt,
                                              &ciphlen)
            || !WPACKET_put_bytes_u8(&hrrpkt, 0)
            || !WPACKET_start_sub_packet_u16(&hrrpkt)) {
        WPACKET_cleanup(&hrrpkt);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_put_bytes_u16(&hrrpkt, TLSEXT_TYPE_supported_versions)
            || !WPACKET_start_sub_packet_u16(&hrrpkt)
            || !WPACKET_put_bytes_u16(&hrrpkt, s->version)
            || !WPACKET_close(&hrrpkt)) {
        WPACKET_cleanup(&hrrpkt);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (key_share) {
        if (!WPACKET_put_bytes_u16(&hrrpkt, TLSEXT_TYPE_key_share)
                || !WPACKET_start_sub_packet_u16(&hrrpkt)
                || !WPACKET_put_bytes_u16(&hrrpkt, s->s3.group_id)
                || !WPACKET_close(&hrrpkt)) {
            WPACKET_cleanup(&hrrpkt);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (!WPACKET_put_bytes_u16(&hrrpkt, TLSEXT_TYPE_cookie)
            || !WPACKET_start_sub_packet_u16(&hrrpkt)
            || !WPACKET_sub_memcpy_u16(&hrrpkt, data, rawlen)
            || !WPACKET_close(&hrrpkt) /* cookie extension */
            || !WPACKET_close(&hrrpkt) /* extension block */
            || !WPACKET_close(&hrrpkt) /* message */
            || !WPACKET_get_total_written(&hrrpkt, &hrrlen)
            || !WPACKET_finish(&hrrpkt)) {
        WPACKET_cleanup(&hrrpkt);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Reconstruct the transcript hash */
    if (!create_synthetic_message_hash(s, PACKET_data(&chhash),
                                       PACKET_remaining(&chhash), hrr,
                                       hrrlen)) {
        /* SSLfatal() already called */
        return 0;
    }

    /* Act as if this ClientHello came after a HelloRetryRequest */
    s->hello_retry_request = 1;

    s->ext.cookieok = 1;
#endif

    return 1;
}

#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
int tls_parse_ctos_supported_groups(SSL *s, PACKET *pkt, unsigned int context,
                                    X509 *x, size_t chainidx)
{
    PACKET supported_groups_list;

    /* Each group is 2 bytes and we must have at least 1. */
    if (!PACKET_as_length_prefixed_2(pkt, &supported_groups_list)
            || PACKET_remaining(&supported_groups_list) == 0
            || (PACKET_remaining(&supported_groups_list) % 2) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_SUPPORTED_GROUPS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit || SSL_IS_TLS13(s)) {
        OPENSSL_free(s->ext.peer_supportedgroups);
        s->ext.peer_supportedgroups = NULL;
        s->ext.peer_supportedgroups_len = 0;
        if (!tls1_save_u16(&supported_groups_list,
                           &s->ext.peer_supportedgroups,
                           &s->ext.peer_supportedgroups_len)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PARSE_CTOS_SUPPORTED_GROUPS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}
#endif

int tls_parse_ctos_ems(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* The extension must always be empty */
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_EMS, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (s->options & SSL_OP_NO_EXTENDED_MASTER_SECRET)
        return 1;

    s->s3.flags |= TLS1_FLAGS_RECEIVED_EXTMS;

    return 1;
}


int tls_parse_ctos_early_data(SSL *s, PACKET *pkt, unsigned int context,
                              X509 *x, size_t chainidx)
{
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_EARLY_DATA, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (s->hello_retry_request != SSL_HRR_NONE) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PARSE_CTOS_EARLY_DATA, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

static SSL_TICKET_STATUS tls_get_stateful_ticket(SSL *s, PACKET *tick,
                                                 SSL_SESSION **sess)
{
    SSL_SESSION *tmpsess = NULL;

    s->ext.ticket_expected = 1;

    switch (PACKET_remaining(tick)) {
        case 0:
            return SSL_TICKET_EMPTY;

        case SSL_MAX_SSL_SESSION_ID_LENGTH:
            break;

        default:
            return SSL_TICKET_NO_DECRYPT;
    }

    tmpsess = lookup_sess_in_cache(s, PACKET_data(tick),
                                   SSL_MAX_SSL_SESSION_ID_LENGTH);

    if (tmpsess == NULL)
        return SSL_TICKET_NO_DECRYPT;

    *sess = tmpsess;
    return SSL_TICKET_SUCCESS;
}

int tls_parse_ctos_psk(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    PACKET identities, binders, binder;
    size_t binderoffset, hashsize;
    SSL_SESSION *sess = NULL;
    unsigned int id, i, ext = 0;
    const EVP_MD *md = NULL;

    /*
     * If we have no PSK kex mode that we recognise then we can't resume so
     * ignore this extension
     */
    if ((s->ext.psk_kex_mode
            & (TLSEXT_KEX_MODE_FLAG_KE | TLSEXT_KEX_MODE_FLAG_KE_DHE)) == 0)
        return 1;

    if (!PACKET_get_length_prefixed_2(pkt, &identities)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PARSE_CTOS_PSK, SSL_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.ticket_expected = 0;
    for (id = 0; PACKET_remaining(&identities) != 0; id++) {
        PACKET identity;
        unsigned long ticket_agel;
        size_t idlen;

        if (!PACKET_get_length_prefixed_2(&identities, &identity)
                || !PACKET_get_net_4(&identities, &ticket_agel)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PARSE_CTOS_PSK, SSL_R_BAD_EXTENSION);
            return 0;
        }

        idlen = PACKET_remaining(&identity);
        if (s->psk_find_session_cb != NULL
                && !s->psk_find_session_cb(s, PACKET_data(&identity), idlen,
                                           &sess)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PARSE_CTOS_PSK, SSL_R_BAD_EXTENSION);
            return 0;
        }

#ifndef OPENSSL_NO_PSK
        if(sess == NULL
                && s->psk_server_callback != NULL
                && idlen <= PSK_MAX_IDENTITY_LEN) {
            char *pskid = NULL;
            unsigned char pskdata[PSK_MAX_PSK_LEN];
            unsigned int pskdatalen;

            if (!PACKET_strndup(&identity, &pskid)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            pskdatalen = s->psk_server_callback(s, pskid, pskdata,
                                                sizeof(pskdata));
            OPENSSL_free(pskid);
            if (pskdatalen > PSK_MAX_PSK_LEN) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            } else if (pskdatalen > 0) {
                const SSL_CIPHER *cipher;
                const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };

                /*
                 * We found a PSK using an old style callback. We don't know
                 * the digest so we default to SHA256 as per the TLSv1.3 spec
                 */
                cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
                if (cipher == NULL) {
                    OPENSSL_cleanse(pskdata, pskdatalen);
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }

                sess = SSL_SESSION_new();
                if (sess == NULL
                        || !SSL_SESSION_set1_master_key(sess, pskdata,
                                                        pskdatalen)
                        || !SSL_SESSION_set_cipher(sess, cipher)
                        || !SSL_SESSION_set_protocol_version(sess,
                                                             TLS1_3_VERSION)) {
                    OPENSSL_cleanse(pskdata, pskdatalen);
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                             ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                OPENSSL_cleanse(pskdata, pskdatalen);
            }
        }
#endif /* OPENSSL_NO_PSK */

        if (sess != NULL) {
            /* We found a PSK */
            SSL_SESSION *sesstmp = ssl_session_dup(sess, 0);

            if (sesstmp == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PARSE_CTOS_PSK, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            SSL_SESSION_free(sess);
            sess = sesstmp;

            /*
             * We've just been told to use this session for this context so
             * make sure the sid_ctx matches up.
             */
            memcpy(sess->sid_ctx, s->sid_ctx, s->sid_ctx_length);
            sess->sid_ctx_length = s->sid_ctx_length;
            ext = 1;
            if (id == 0)
                s->ext.early_data_ok = 1;
            s->ext.ticket_expected = 1;
        } else {
            uint32_t ticket_age = 0, now, agesec, agems;
            int ret;

            /*
             * If we are using anti-replay protection then we behave as if
             * SSL_OP_NO_TICKET is set - we are caching tickets anyway so there
             * is no point in using full stateless tickets.
             */
            if ((s->options & SSL_OP_NO_TICKET) != 0
                    || (s->max_early_data > 0
                        && (s->options & SSL_OP_NO_ANTI_REPLAY) == 0))
                ret = tls_get_stateful_ticket(s, &identity, &sess);
            else
                ret = tls_decrypt_ticket(s, PACKET_data(&identity),
                                         PACKET_remaining(&identity), NULL, 0,
                                         &sess);

            if (ret == SSL_TICKET_EMPTY) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                         SSL_R_BAD_EXTENSION);
                return 0;
            }

            if (ret == SSL_TICKET_FATAL_ERR_MALLOC
                    || ret == SSL_TICKET_FATAL_ERR_OTHER) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PARSE_CTOS_PSK, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            if (ret == SSL_TICKET_NONE || ret == SSL_TICKET_NO_DECRYPT)
                continue;

            /* Check for replay */
            if (s->max_early_data > 0
                    && (s->options & SSL_OP_NO_ANTI_REPLAY) == 0
                    && !SSL_CTX_remove_session(s->session_ctx, sess)) {
                SSL_SESSION_free(sess);
                sess = NULL;
                continue;
            }

            ticket_age = (uint32_t)ticket_agel;
            now = (uint32_t)time(NULL);
            agesec = now - (uint32_t)sess->time;
            agems = agesec * (uint32_t)1000;
            ticket_age -= sess->ext.tick_age_add;

            /*
             * For simplicity we do our age calculations in seconds. If the
             * client does it in ms then it could appear that their ticket age
             * is longer than ours (our ticket age calculation should always be
             * slightly longer than the client's due to the network latency).
             * Therefore we add 1000ms to our age calculation to adjust for
             * rounding errors.
             */
            if (id == 0
                    && sess->timeout >= (long)agesec
                    && agems / (uint32_t)1000 == agesec
                    && ticket_age <= agems + 1000
                    && ticket_age + TICKET_AGE_ALLOWANCE >= agems + 1000) {
                /*
                 * Ticket age is within tolerance and not expired. We allow it
                 * for early data
                 */
                s->ext.early_data_ok = 1;
            }
        }

        md = ssl_md(s->ctx, sess->cipher->algorithm2);
        if (!EVP_MD_is_a(md,
                EVP_MD_name(ssl_md(s->ctx, s->s3.tmp.new_cipher->algorithm2)))) {
            /* The ciphersuite is not compatible with this session. */
            SSL_SESSION_free(sess);
            sess = NULL;
            s->ext.early_data_ok = 0;
            s->ext.ticket_expected = 0;
            continue;
        }
        break;
    }

    if (sess == NULL)
        return 1;

    binderoffset = PACKET_data(pkt) - (const unsigned char *)s->init_buf->data;
    hashsize = EVP_MD_size(md);

    if (!PACKET_get_length_prefixed_2(pkt, &binders)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                 SSL_R_BAD_EXTENSION);
        goto err;
    }

    for (i = 0; i <= id; i++) {
        if (!PACKET_get_length_prefixed_1(&binders, &binder)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                     SSL_R_BAD_EXTENSION);
            goto err;
        }
    }

    if (PACKET_remaining(&binder) != hashsize) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_PSK,
                 SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tls_psk_do_binder(s, md, (const unsigned char *)s->init_buf->data,
                          binderoffset, PACKET_data(&binder), NULL, sess, 0,
                          ext) != 1) {
        /* SSLfatal() already called */
        goto err;
    }

    s->ext.tick_identity = id;

    SSL_SESSION_free(s->session);
    s->session = sess;
    return 1;
err:
    SSL_SESSION_free(sess);
    return 0;
}

int tls_parse_ctos_post_handshake_auth(SSL *s, PACKET *pkt, unsigned int context,
                                       X509 *x, size_t chainidx)
{
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_POST_HANDSHAKE_AUTH,
                 SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR);
        return 0;
    }

    s->post_handshake_auth = SSL_PHA_EXT_RECEIVED;

    return 1;
}

/*
 * Add the server's renegotiation binding
 */
EXT_RETURN tls_construct_stoc_renegotiate(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (!s->s3.send_connection_binding)
        return EXT_RETURN_NOT_SENT;

    /* Still add this even if SSL_OP_NO_RENEGOTIATION is set */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_renegotiate)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
            || !WPACKET_memcpy(pkt, s->s3.previous_client_finished,
                               s->s3.previous_client_finished_len)
            || !WPACKET_memcpy(pkt, s->s3.previous_server_finished,
                               s->s3.previous_server_finished_len)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_RENEGOTIATE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_server_name(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->servername_done != 1)
        return EXT_RETURN_NOT_SENT;

    /*
     * Prior to TLSv1.3 we ignore any SNI in the current handshake if resuming.
     * We just use the servername from the initial handshake.
     */
    if (s->hit && !SSL_IS_TLS13(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_SERVER_NAME,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/* Add/include the server's max fragment len extension into ServerHello */
EXT_RETURN tls_construct_stoc_maxfragmentlen(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (!USE_MAX_FRAGMENT_LENGTH_EXT(s->session))
        return EXT_RETURN_NOT_SENT;

    /*-
     * 4 bytes for this extension type and extension length
     * 1 byte for the Max Fragment Length code value.
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_max_fragment_length)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, s->session->ext.max_fragment_len_mode)
        || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_MAXFRAGMENTLEN, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENSSL_NO_EC
EXT_RETURN tls_construct_stoc_ec_pt_formats(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    unsigned long alg_k = s->s3.tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3.tmp.new_cipher->algorithm_auth;
    int using_ecc = ((alg_k & SSL_kECDHE) || (alg_a & SSL_aECDSA))
                    && (s->ext.peer_ecpointformats != NULL);
    const unsigned char *plist;
    size_t plistlen;

    if (!using_ecc)
        return EXT_RETURN_NOT_SENT;

    tls1_get_formatlist(s, &plist, &plistlen);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ec_point_formats)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, plist, plistlen)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_EC_PT_FORMATS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
EXT_RETURN tls_construct_stoc_supported_groups(SSL *s, WPACKET *pkt,
                                               unsigned int context, X509 *x,
                                               size_t chainidx)
{
    const uint16_t *groups;
    size_t numgroups, i, first = 1;

    /* s->s3.group_id is non zero if we accepted a key_share */
    if (s->s3.group_id == 0)
        return EXT_RETURN_NOT_SENT;

    /* Get our list of supported groups */
    tls1_get_supported_groups(s, &groups, &numgroups);
    if (numgroups == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /* Copy group ID if supported */
    for (i = 0; i < numgroups; i++) {
        uint16_t group = groups[i];

        if (tls_valid_group(s, group, SSL_version(s))
                && tls_group_allowed(s, group, SSL_SECOP_CURVE_SUPPORTED)) {
            if (first) {
                /*
                 * Check if the client is already using our preferred group. If
                 * so we don't need to add this extension
                 */
                if (s->s3.group_id == group)
                    return EXT_RETURN_NOT_SENT;

                /* Add extension header */
                if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_groups)
                           /* Sub-packet for supported_groups extension */
                        || !WPACKET_start_sub_packet_u16(pkt)
                        || !WPACKET_start_sub_packet_u16(pkt)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                             SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS,
                             ERR_R_INTERNAL_ERROR);
                    return EXT_RETURN_FAIL;
                }

                first = 0;
            }
            if (!WPACKET_put_bytes_u16(pkt, group)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                             SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS,
                             ERR_R_INTERNAL_ERROR);
                    return EXT_RETURN_FAIL;
                }
        }
    }

    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_stoc_session_ticket(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (!s->ext.ticket_expected || !tls_use_ticket(s)) {
        s->ext.ticket_expected = 0;
        return EXT_RETURN_NOT_SENT;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_SESSION_TICKET, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENSSL_NO_OCSP
EXT_RETURN tls_construct_stoc_status_request(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    /* We don't currently support this extension inside a CertificateRequest */
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)
        return EXT_RETURN_NOT_SENT;

    if (!s->ext.status_expected)
        return EXT_RETURN_NOT_SENT;

    if (SSL_IS_TLS13(s) && chainidx != 0)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * In TLSv1.3 we include the certificate status itself. In <= TLSv1.2 we
     * send back an empty extension, with the certificate status appearing as a
     * separate message
     */
    if (SSL_IS_TLS13(s) && !tls_construct_cert_status_body(s, pkt)) {
       /* SSLfatal() already called */
       return EXT_RETURN_FAIL;
    }
    if (!WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
EXT_RETURN tls_construct_stoc_next_proto_neg(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    const unsigned char *npa;
    unsigned int npalen;
    int ret;
    int npn_seen = s->s3.npn_seen;

    s->s3.npn_seen = 0;
    if (!npn_seen || s->ctx->ext.npn_advertised_cb == NULL)
        return EXT_RETURN_NOT_SENT;

    ret = s->ctx->ext.npn_advertised_cb(s, &npa, &npalen,
                                        s->ctx->ext.npn_advertised_cb_arg);
    if (ret == SSL_TLSEXT_ERR_OK) {
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
                || !WPACKET_sub_memcpy_u16(pkt, npa, npalen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_STOC_NEXT_PROTO_NEG,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->s3.npn_seen = 1;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_stoc_alpn(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    if (s->s3.alpn_selected == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, s->s3.alpn_selected,
                                      s->s3.alpn_selected_len)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_ALPN, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENSSL_NO_SRTP
EXT_RETURN tls_construct_stoc_use_srtp(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    if (s->srtp_profile == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, 2)
            || !WPACKET_put_bytes_u16(pkt, s->srtp_profile->id)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_USE_SRTP,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_stoc_etm(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (!s->ext.use_etm)
        return EXT_RETURN_NOT_SENT;

    /*
     * Don't use encrypt_then_mac if AEAD or RC4 might want to disable
     * for other cases too.
     */
    if (s->s3.tmp.new_cipher->algorithm_mac == SSL_AEAD
        || s->s3.tmp.new_cipher->algorithm_enc == SSL_RC4
        || s->s3.tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT
        || s->s3.tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12) {
        s->ext.use_etm = 0;
        return EXT_RETURN_NOT_SENT;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_ETM,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_ems(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if ((s->s3.flags & TLS1_FLAGS_RECEIVED_EXTMS) == 0)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_extended_master_secret)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_EMS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_supported_versions(SSL *s, WPACKET *pkt,
                                                 unsigned int context, X509 *x,
                                                 size_t chainidx)
{
    if (!ossl_assert(SSL_IS_TLS13(s))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_VERSIONS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_versions)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, s->version)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_VERSIONS,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_key_share(SSL *s, WPACKET *pkt,
                                        unsigned int context, X509 *x,
                                        size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned char *encodedPoint;
    size_t encoded_pt_len = 0;
    EVP_PKEY *ckey = s->s3.peer_tmp, *skey = NULL;

    if (s->hello_retry_request == SSL_HRR_PENDING) {
        if (ckey != NULL) {
            /* Original key_share was acceptable so don't ask for another one */
            return EXT_RETURN_NOT_SENT;
        }
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
                || !WPACKET_start_sub_packet_u16(pkt)
                || !WPACKET_put_bytes_u16(pkt, s->s3.group_id)
                || !WPACKET_close(pkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE,
                     ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }

        return EXT_RETURN_SENT;
    }

    if (ckey == NULL) {
        /* No key_share received from client - must be resuming */
        if (!s->hit || !tls13_generate_handshake_secret(s, NULL, 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        return EXT_RETURN_NOT_SENT;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, s->s3.group_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    skey = ssl_generate_pkey(s, ckey);
    if (skey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE,
                 ERR_R_MALLOC_FAILURE);
        return EXT_RETURN_FAIL;
    }

    /* Generate encoding of server key */
    encoded_pt_len = EVP_PKEY_get1_tls_encodedpoint(skey, &encodedPoint);
    if (encoded_pt_len == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE,
                 ERR_R_EC_LIB);
        EVP_PKEY_free(skey);
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_sub_memcpy_u16(pkt, encodedPoint, encoded_pt_len)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE,
                 ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(skey);
        OPENSSL_free(encodedPoint);
        return EXT_RETURN_FAIL;
    }
    OPENSSL_free(encodedPoint);

    /* This causes the crypto state to be updated based on the derived keys */
    s->s3.tmp.pkey = skey;
    if (ssl_derive(s, skey, ckey, 1) == 0) {
        /* SSLfatal() already called */
        return EXT_RETURN_FAIL;
    }
    return EXT_RETURN_SENT;
#else
    return EXT_RETURN_FAIL;
#endif
}

EXT_RETURN tls_construct_stoc_cookie(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3
    unsigned char *hashval1, *hashval2, *appcookie1, *appcookie2, *cookie;
    unsigned char *hmac, *hmac2;
    size_t startlen, ciphlen, totcookielen, hashlen, hmaclen, appcookielen;
    EVP_MD_CTX *hctx;
    EVP_PKEY *pkey;
    int ret = EXT_RETURN_FAIL;

    if ((s->s3.flags & TLS1_FLAGS_STATELESS) == 0)
        return EXT_RETURN_NOT_SENT;

    if (s->ctx->gen_stateless_cookie_cb == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 SSL_R_NO_COOKIE_CALLBACK_SET);
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_cookie)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_get_total_written(pkt, &startlen)
            || !WPACKET_reserve_bytes(pkt, MAX_COOKIE_SIZE, &cookie)
            || !WPACKET_put_bytes_u16(pkt, COOKIE_STATE_FORMAT_VERSION)
            || !WPACKET_put_bytes_u16(pkt, TLS1_3_VERSION)
            || !WPACKET_put_bytes_u16(pkt, s->s3.group_id)
            || !s->method->put_cipher_by_char(s->s3.tmp.new_cipher, pkt,
                                              &ciphlen)
               /* Is there a key_share extension present in this HRR? */
            || !WPACKET_put_bytes_u8(pkt, s->s3.peer_tmp == NULL)
            || !WPACKET_put_bytes_u32(pkt, (unsigned int)time(NULL))
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_reserve_bytes(pkt, EVP_MAX_MD_SIZE, &hashval1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * Get the hash of the initial ClientHello. ssl_handshake_hash() operates
     * on raw buffers, so we first reserve sufficient bytes (above) and then
     * subsequently allocate them (below)
     */
    if (!ssl3_digest_cached_records(s, 0)
            || !ssl_handshake_hash(s, hashval1, EVP_MAX_MD_SIZE, &hashlen)) {
        /* SSLfatal() already called */
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_allocate_bytes(pkt, hashlen, &hashval2)
            || !ossl_assert(hashval1 == hashval2)
            || !WPACKET_close(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)
            || !WPACKET_reserve_bytes(pkt, SSL_COOKIE_LENGTH, &appcookie1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /* Generate the application cookie */
    if (s->ctx->gen_stateless_cookie_cb(s, appcookie1, &appcookielen) == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_allocate_bytes(pkt, appcookielen, &appcookie2)
            || !ossl_assert(appcookie1 == appcookie2)
            || !WPACKET_close(pkt)
            || !WPACKET_get_total_written(pkt, &totcookielen)
            || !WPACKET_reserve_bytes(pkt, SHA256_DIGEST_LENGTH, &hmac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    hmaclen = SHA256_DIGEST_LENGTH;

    totcookielen -= startlen;
    if (!ossl_assert(totcookielen <= MAX_COOKIE_SIZE - SHA256_DIGEST_LENGTH)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /* HMAC the cookie */
    hctx = EVP_MD_CTX_create();
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                        s->session_ctx->ext.cookie_hmac_key,
                                        sizeof(s->session_ctx->ext
                                               .cookie_hmac_key));
    if (hctx == NULL || pkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestSignInit(hctx, NULL, EVP_sha256(), NULL, pkey) <= 0
            || EVP_DigestSign(hctx, hmac, &hmaclen, cookie,
                              totcookielen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!ossl_assert(totcookielen + hmaclen <= MAX_COOKIE_SIZE)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!WPACKET_allocate_bytes(pkt, hmaclen, &hmac2)
            || !ossl_assert(hmac == hmac2)
            || !ossl_assert(cookie == hmac - totcookielen)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_COOKIE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = EXT_RETURN_SENT;

 err:
    EVP_MD_CTX_free(hctx);
    EVP_PKEY_free(pkey);
    return ret;
#else
    return EXT_RETURN_FAIL;
#endif
}

EXT_RETURN tls_construct_stoc_cryptopro_bug(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    const unsigned char cryptopro_ext[36] = {
        0xfd, 0xe8,         /* 65000 */
        0x00, 0x20,         /* 32 bytes length */
        0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
        0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
        0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08,
        0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17
    };

    if (((s->s3.tmp.new_cipher->id & 0xFFFF) != 0x80
         && (s->s3.tmp.new_cipher->id & 0xFFFF) != 0x81)
            || (SSL_get_options(s) & SSL_OP_CRYPTOPRO_TLSEXT_BUG) == 0)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_memcpy(pkt, cryptopro_ext, sizeof(cryptopro_ext))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_CRYPTOPRO_BUG, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_early_data(SSL *s, WPACKET *pkt,
                                         unsigned int context, X509 *x,
                                         size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_NEW_SESSION_TICKET) {
        if (s->max_early_data == 0)
            return EXT_RETURN_NOT_SENT;

        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_early_data)
                || !WPACKET_start_sub_packet_u16(pkt)
                || !WPACKET_put_bytes_u32(pkt, s->max_early_data)
                || !WPACKET_close(pkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }

        return EXT_RETURN_SENT;
    }

    if (s->ext.early_data != SSL_EARLY_DATA_ACCEPTED)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_early_data)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA,
                 ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_psk(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (!s->hit)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_psk)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, s->ext.tick_identity)
            || !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_STOC_PSK, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

// ESNI_DOXY_START
#ifndef OPENSSL_NO_ESNI
/**
 * @brief Decodes inbound ESNI extension into SSL_ESNI structure
 *
 * The ESNI stuff:
 *
 * <pre>
 *     struct {
 *        CipherSuite suite; from c->ciphersuite (SSL_CIPHER)
 *        KeyShareEntry key_share; from c->encoded_keshare (buffer)
 *        opaque record_digest<0..2^16-1>; from c->record_digest (buffer)
 *        opaque encrypted_sni<0..2^16-1>; from c->encrypted_sni (buffer)
 *     } ClientEncryptedSNI;
 * </pre>
 * 
 * Parse, decrypt etc inbound ESNI extension.
 */
int tls_parse_ctos_esni(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    CLIENT_ESNI *ce=NULL;
    SSL_ESNI *match=NULL;

    /* 
     * Check if we've been configured to hard fail on ESNI failure
     * (SHOULD be off by default, so that GREASE works)
     */
    int server_fail_grease=(s->options & SSL_OP_ESNI_HARDFAIL); 
    /*
     * Note that someone tried
     */
    OSSL_TRACE_BEGIN(TLS) {

        time_t now=time(0);
        struct tm *tnow=gmtime(&now);
        char *anow=asctime(tnow);
        int sockfd=0;
        int res=0;
        char clientip[INET6_ADDRSTRLEN]; 
        memset(clientip,0,INET6_ADDRSTRLEN);
        strncpy(clientip,"dunno",INET6_ADDRSTRLEN);
        struct sockaddr_storage ss;
        socklen_t salen = sizeof(ss);
        struct sockaddr *sa;
        memset(&ss,0,salen);
        sa = (struct sockaddr *)&ss;
        res=BIO_get_fd(s->rbio,&sockfd);
        if (res!=-1) {
            res = getpeername(sockfd,sa,&salen);
            if (res==0) res=getnameinfo(sa,salen,clientip,INET6_ADDRSTRLEN, 0,0,NI_NUMERICHOST);
            if (res!=0) strncpy(clientip,"dunno",INET6_ADDRSTRLEN);
        }
        BIO_printf(trc_out,"Got ESNI from %s at %s",clientip,anow);

    } OSSL_TRACE_END(TLS);

    s->esni_attempted=1;
    if (s->esni==NULL) {
        /*
         * No ESNIKeys loaded so we'll ignore the crap out
         * of whatever the client asked for, other than noting
         * it so's we can grease the answer (if we wanna)
         * TODO(ESNI): add flag to SSL state for this case
         */
        if (server_fail_grease==0) {
            /*
             * ignore the problem
             */
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Exiting tls_parse_ctos_esni at %d\n",__LINE__);
            } OSSL_TRACE_END(TLS);
            return 1;
        } else {
            /*
             * hardfail
             */
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Exiting tls_parse_ctos_esni at %d\n",__LINE__);
            } OSSL_TRACE_END(TLS);
            return 0;
        }
    }

    /*
     * We need the encoded key share from the h/s to be set or else
     * ESNI won't work (the encoded key share is used as the AAD
     * when decrypting)
     */
    if (s->ext.kse_len==0 || s->ext.kse==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    ce=OPENSSL_malloc(sizeof(CLIENT_ESNI));
    if (ce==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }
    memset(ce,0,sizeof(CLIENT_ESNI));

    unsigned char cipher[TLS_CIPHER_LEN];
    memset(&cipher,0,TLS_CIPHER_LEN);
    if (!PACKET_copy_bytes(pkt, cipher, TLS_CIPHER_LEN)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                 SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->ciphersuite = cipher[0]*256+cipher[1];
    uint16_t group_id=0;
    unsigned int tmp;
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>0xffff) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    group_id=(uint16_t)tmp;

    /*
     * Code below is highly repetitive but that's ok for now, as the
     * extension structure is quite likely to change. Depending on
     * how it changes, there may be an opportunity to reduce the LOC
     * here.
     */

    /* key_share len - should be 0x20 */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    /* sanity check */
    if (tmp > (OPENSSL_DH_MAX_MODULUS_BITS/8)) { /* actually 10000 integer DH bits is supported! */
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    unsigned char *tmpbuf=OPENSSL_malloc(tmp);  //* group id goes there too - sigh as always
    if (tmpbuf==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, tmpbuf, tmp)) {
        OPENSSL_free(tmpbuf);
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->encoded_keyshare=SSL_ESNI_wrap_keyshare(tmpbuf,tmp,group_id,&ce->encoded_keyshare_len);
    OPENSSL_free(tmpbuf);
    if (ce->encoded_keyshare==NULL ){
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }

    /* record_digest len - should also be 0x20 */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > EVP_MAX_MD_SIZE) { /* MAX_MD_SIZE is biggest hash which works here */
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }

    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->record_digest=OPENSSL_malloc(tmp);
    if (ce->record_digest==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, ce->record_digest, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->record_digest_len=tmp;

    /* encrypted_sni len */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > MAX_ESNI_CIPHER_SIZE) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->encrypted_sni=OPENSSL_malloc(tmp);
    if (ce->encrypted_sni==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, ce->encrypted_sni, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
         SSL_R_BAD_EXTENSION);
        goto err;
    }
    ce->encrypted_sni_len=tmp;


    /*
     * We need the TLS h/s CH.random and key_share to attempt 
     * decryption. Set those up now in case we need to do
     * trial decruptions if there's a fake record digest
     */
    unsigned char rd[1024];
    size_t rd_len=SSL_get_client_random(s,rd,1024);
    uint16_t curve_id = s->s3.group_id;
    unsigned char *encservername=NULL;
    size_t encservername_len=0;

    /*
     * see which pub/private value matches record_digest 
     */
    int matchind=-1;
    match=NULL; // more as a reminder to self:-)
    int i; /* loop counter - android build doesn't like C99;-( */
    for (i=0;i!=s->nesni && matchind==-1;i++) {
        if (s->esni[i].rd_len==ce->record_digest_len &&
            !memcmp(s->esni[i].rd,ce->record_digest,ce->record_digest_len)) {
            /* found it */
            match=&s->esni[i];
            matchind=i;
            break;
        }
    }

    int trial_decryption_success=0;

    if (matchind==-1 || match==NULL) {
        /*
         * Possible trial decryption if so-configured
         */
        int trial_decryption=(s->options & SSL_OP_ESNI_TRIALDECRYPT); 
        if (trial_decryption!=0) {
            matchind=-1;
            match=NULL;
            int i; /* loop counter - android build doesn't like C99;-( */
            for (i=0;trial_decryption_success==0 && i!=s->nesni && matchind==-1;i++) {
                /* add CLIENT_ESNI to the state temporarily */
                s->esni[i].the_esni=ce; 
                s->esni[i].hrr_swap=s->hello_retry_request;
                encservername=SSL_ESNI_dec(s->ctx,s,&s->esni[i],rd_len,rd,curve_id,s->ext.kse_len,s->ext.kse,&encservername_len);
                if (encservername!=NULL) {
                    /*
                     * Yay! it worked
                     */
                    trial_decryption_success=1;
                    match=&s->esni[i];
                    /* zap CLIENT_ESNI from the state - will be put back in a sec if all good */
                    match->the_esni=NULL; 
                    matchind=i;
                    break;
                } 
                /* zap CLIENT_ESNI from the state */
                s->esni[i].the_esni=NULL; 
            }
        } 
        if (trial_decryption_success==0) {
            if (server_fail_grease!=0) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                SSL_R_BAD_EXTENSION);
                goto err;
            } else {
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out,"Exiting tls_parse_ctos_esni at %d\n",__LINE__);
                } OSSL_TRACE_END(TLS);
                goto noerr;
            }
        }
    }
    if (match->the_esni!=NULL) {
        if(match->the_esni->encoded_keyshare!=NULL) OPENSSL_free(match->the_esni->encoded_keyshare);
        if(match->the_esni->record_digest!=NULL) OPENSSL_free(match->the_esni->record_digest);
        if(match->the_esni->encrypted_sni!=NULL) OPENSSL_free(match->the_esni->encrypted_sni);
        OPENSSL_free(match->the_esni); 
    }
    match->the_esni=ce; 

    if (trial_decryption_success==0) {
        /*
         * This is where we matched the record_digest and didn't yet decrypt
         * via trial decryption
         */
        match->hrr_swap=s->hello_retry_request;
        encservername=SSL_ESNI_dec(s->ctx,s,match,rd_len,rd,curve_id,s->ext.kse_len,s->ext.kse,&encservername_len);
        if (encservername==NULL) {
            if (server_fail_grease!=0) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                SSL_R_BAD_EXTENSION);
                goto err;
            } else {
                /* softfail exit */
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out,"Exiting tls_parse_ctos_esni at %d\n",__LINE__);
                } OSSL_TRACE_END(TLS);
                goto noerr;
            }
        }
    }

    /*
     * I think (gulp!) the above is the last softfail exit as we've now
     * managed to decrypt the ESNI presented, so it's "real" - if we 
     * now find crap inside that, then we hard fail
     */

    /*
     * check encservername has no zero bytes internally
     * code here inspired by PACKET_contains_zero_byte but
     * decided not to create a new pseudo-PACKET to do 
     * that
     */
    if (memchr(encservername, 0, encservername_len) != NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
             SSL_R_BAD_EXTENSION);
        goto err;
    }

    /*
     * Now apply esni by swapping out hostname  (all that work just for this:-)
     */
    if (s->ext.hostname != NULL && match->clear_sni!=NULL) {
        OPENSSL_free(match->clear_sni);
    }
    match->clear_sni=s->ext.hostname;
    s->ext.hostname=OPENSSL_strdup((char*)encservername);
    if (s->ext.hostname==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
            SSL_R_BAD_EXTENSION);
        goto err;
    }

    /*
     * mimic the checks made earlier for plaintext SNI 
     * TBH, I'm not sure of the impact of these, but I
     * think the effect is the same. (But I've no clue
     * what s->hit is for.)
     */
    if (s->hit) {
        s->servername_done = 1;
    } else {
        s->servername_done = (s->session->ext.hostname != NULL)
            && !strncasecmp(s->ext.hostname, s->session->ext.hostname,
                            strlen(s->session->ext.hostname));

        if (!s->servername_done && s->session->ext.hostname != NULL)
            s->ext.early_data_ok = 0;
    }
    
    /*
     * copy the name once more:-)
     */
    if (s->session->ext.hostname==NULL) {
        s->session->ext.hostname=OPENSSL_strdup((char*)encservername);
        if (s->session->ext.hostname==NULL) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
                SSL_R_BAD_EXTENSION);
            goto err;
        }
    }

    /* 
     * now set the other name copies for posterity and printing
     * s->ext.hostname is the business end though and the only
     * one used for keying
     */
    if (s->ext.encservername!=NULL) {
        OPENSSL_free(s->ext.encservername);
        s->ext.encservername=NULL;
    }
    s->ext.encservername=OPENSSL_strdup(s->ext.hostname);
    /* no clear_sni in server */
    if (s->ext.clear_sni!=NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
             SSL_R_BAD_EXTENSION);
        goto err;
    }
	s->ext.clear_sni=OPENSSL_strdup(match->clear_sni);
	if (match->clear_sni!=NULL && s->ext.clear_sni==NULL) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
			SSL_R_BAD_EXTENSION);
		goto err;
	}
    /* copy the public_name */
    if (s->ext.public_name!=NULL) {
        OPENSSL_free(s->ext.public_name);
        s->ext.public_name=NULL;
    }
    s->ext.public_name=OPENSSL_strdup(match->public_name);
	if (match->public_name!=NULL && s->ext.public_name==NULL) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ESNI,
			SSL_R_BAD_EXTENSION);
		goto err;
	}
    /*
     * ESNI has now worked, as far as we're concerned
     */
    s->esni_done=1;


    /*
     * call callback
     */
    if (s->esni_cb != NULL) {
        char pstr[ESNI_PBUF_SIZE+1];
        memset(pstr,0,ESNI_PBUF_SIZE+1);
        BIO *biom = BIO_new(BIO_s_mem());
        SSL_ESNI_print(biom,s->esni,matchind);
        BIO_read(biom,pstr,ESNI_PBUF_SIZE);
        unsigned int cbrv=s->esni_cb(s,pstr);
        BIO_free(biom);
        if (cbrv != 1) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Exiting tls_parse_ctos_esni at %d\n",__LINE__);
            } OSSL_TRACE_END(TLS);
            return 0;
        }
    }

    if (s->session!=NULL) {
        /* 
         * set hostname, public_name, clear_sni, encservername in the session 
         * Note that we set hostname to the ESNI value (if present) as that
         * is what'd be needed for any access control. That's a bit bad as
         * the client side doesn't do that (hostname there reflects the 
         * cleartext-SNI/clear_sni).
         */
        if (s->session->ext.encservername!=NULL) {
            OPENSSL_free(s->session->ext.encservername);
        }
        s->session->ext.encservername=OPENSSL_strdup(s->ext.hostname);
        if (s->session->ext.clear_sni!=NULL) {
            OPENSSL_free(s->session->ext.clear_sni);
        }
        s->session->ext.clear_sni=OPENSSL_strdup(s->ext.clear_sni);
        if (s->session->ext.public_name!=NULL) {
            OPENSSL_free(s->session->ext.public_name);
        }
        s->session->ext.public_name=OPENSSL_strdup(s->ext.public_name);

    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"Happy exit from tls_parse_ctos_esni at %d\n",__LINE__);
    } OSSL_TRACE_END(TLS);

    return 1;

noerr:

    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"noerr from %s at %d\n",__FUNCTION__,__LINE__);
        SSL_ESNI_print(trc_out,s->esni,ESNI_SELECT_ALL);
    } OSSL_TRACE_END(TLS);

    if (ce->encoded_keyshare) OPENSSL_free(ce->encoded_keyshare);
    if (ce->record_digest) OPENSSL_free(ce->record_digest);
    if (ce->encrypted_sni) OPENSSL_free(ce->encrypted_sni);
    if (ce) OPENSSL_free(ce);
    if (s->esni && match!=NULL) {
        match->the_esni=NULL;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"Less happy exit from tls_parse_ctos_esni at %d\n",__LINE__);
    } OSSL_TRACE_END(TLS);
    return 1;

err:

    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"err from %s at %d\n",__FUNCTION__,__LINE__);
        SSL_ESNI_print(trc_out,s->esni,ESNI_SELECT_ALL);
    } OSSL_TRACE_END(TLS);

    if (ce->encoded_keyshare) OPENSSL_free(ce->encoded_keyshare);
    if (ce->record_digest) OPENSSL_free(ce->record_digest);
    if (ce->encrypted_sni) OPENSSL_free(ce->encrypted_sni);
    if (ce) OPENSSL_free(ce);
    if (s->esni && match!=NULL) {
        match->the_esni=NULL;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"Unhappy exit from tls_parse_ctos_esni at %d\n",__LINE__);
    } OSSL_TRACE_END(TLS);

    return 0;
}

/**
 * @brief If ESNI all went well, and we have a nonce then send that back
 *
 * Just do the biz... :-)
 */
EXT_RETURN tls_construct_stoc_esni(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->esni) {
        if (s->esni_done==1) {
            SSL_ESNI *match=NULL;
            int i; /* loop counter - android build doesn't like C99;-( */
            for (i=0;i!=s->nesni;i++) {
                if (s->esni[i].nonce!=NULL) {
                    match=&s->esni[i];
                } 
            }
            if (match==NULL) {
                return EXT_RETURN_FAIL;
            }
            if  (match->nonce==NULL || match->nonce_len<=0) {
                return EXT_RETURN_FAIL;
            }
            /*
             * For draft-02 we only include the nonce in the 
             * respose. For draft-03/04 there's more structure:
             *  enum {
             *      esni_accept(0),
             *      esni_retry_request(1),
             *  } ServerESNIResponseType;
             * 
             * struct {
             *      ServerESNIResponseType response_type;
             *      select (response_type) {
             *          case esni_accept:        uint8 nonce[16];
             *          case esni_retry_request: ESNIKeys retry_keys<1..2^16-1>;
             *          }
             * } ServerEncryptedSNI;
             *
             */
            if (match->version==ESNI_DRAFT_02_VERSION) {
                if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_esni)
                    || !WPACKET_put_bytes_u16(pkt, match->nonce_len)
                    || !WPACKET_memcpy(pkt, match->nonce, match->nonce_len)) {
                    return EXT_RETURN_FAIL;
                }
                return EXT_RETURN_SENT;
            } else { // for draft-03 or draft-04
                if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_esni)
                    || !WPACKET_put_bytes_u16(pkt, match->nonce_len+1)
                    || !WPACKET_put_bytes_u8(pkt, 0) 
                    || !WPACKET_memcpy(pkt, match->nonce, match->nonce_len)) {
                    return EXT_RETURN_FAIL;
                }
                return EXT_RETURN_SENT;
            }
        } else if (s->esni_attempted == 1 ) {
            /*
             * We've either been GREASEd or the client went wonky and decryption failed
             * so cause sending first ESNIKeys value that may work if the client re-tries
             */
            unsigned char *rrval=s->esni[0].encoded_rr;
            size_t rrlen=s->esni[0].encoded_rr_len;
            if (rrlen==0 || rrval==NULL) {
                /*
                 * bummer, shouldn't happen so fail hard
                 */
                return EXT_RETURN_FAIL;
            } 
            /*
             * send the encoded RR value as the content of the EncryptedExtension
             */
            if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_esni)
                    || !WPACKET_put_bytes_u16(pkt, rrlen+1)
                    || !WPACKET_put_bytes_u8(pkt, 1) 
                    || !WPACKET_memcpy(pkt, rrval, rrlen)) {
                    return EXT_RETURN_FAIL;
            }
            return EXT_RETURN_SENT;
        } else { 
            /*
             * We got a request with no ESNI at all, do nowt
             */
            return EXT_RETURN_NOT_SENT;
        }
    } else if (s->esni_attempted==1) {
        /*
         * In this case, if we've been greased or mistakenly sent an ESNI
         * but we have no ESNI keys loaded, so we'll randomly send a 
         * fake nonce or fake esnikeys
         */
        int randind=0;
        int rv=RAND_bytes((unsigned char*)&randind,sizeof(randind));
        if (rv!=1) {
            return EXT_RETURN_FAIL;
        }
        /*
         * we'll produce a fake nonce 2/3rds of the time
         * when fakekeyRnonce is zero, adjust the proportions
         * to taste - if you want fewer fake keys, then change
         * the 3 below to something bigger
         */
        int fakekeyRnonce=(randind%3);
        int fakelen=16;
        if (fakekeyRnonce==0) { 
            /*
             * fake ESNIKeys length, we'll vary that a bit too
             */
            fakelen=80+(randind%32);
        } 
        unsigned char fakebuf[fakelen];
        rv=RAND_bytes(fakebuf,fakelen);
        if (rv!=1) {
            return EXT_RETURN_FAIL;
        }
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_esni)
                || !WPACKET_put_bytes_u16(pkt, fakelen+1)
                || !WPACKET_put_bytes_u8(pkt, (fakekeyRnonce==0?1:0))
                || !WPACKET_memcpy(pkt, fakebuf, fakelen)) {
                return EXT_RETURN_FAIL;
        }
        return EXT_RETURN_SENT;
    }
    return EXT_RETURN_NOT_SENT;

}
#endif // END_OPENSSL_NO_ESNI

#ifndef OPENSSL_NO_ECH

/**
 * @brief wrapper for hpke_dec since we call it >1 time
 */
static unsigned char *hpke_decrypt_encch(SSL_ECH *ech, size_t *innerlen)
{
    size_t publen=0; unsigned char *pub=NULL;
    size_t cipherlen=0; unsigned char *cipher=NULL;
    size_t senderpublen=0; unsigned char *senderpub=NULL;
    size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    cipherlen=ech->the_ech->payload_len;
    cipher=ech->the_ech->payload;
    senderpublen=ech->the_ech->enc_len;
    senderpub=ech->the_ech->enc;
    /*
     * We only support one ECHConfig for now on the server side
     */
    publen=ech->cfg->recs[0].pub_len-4;
    pub=ech->cfg->recs[0].pub+4;
    ech->crypto_started=1;

    ech_pbuf("pub",pub,publen);
    ech_pbuf("senderpub",senderpub,senderpublen);
    ech_pbuf("cipher",cipher,cipherlen);

    int rv=hpke_dec( hpke_mode, hpke_suite,
                NULL, 0, NULL, // pskid, psk
                //publen, pub, // recipient public key
                0, NULL,
                0,NULL,ech->keyshare, // private key in EVP_PKEY form
                senderpublen, senderpub, // sender public
                cipherlen, cipher, // ciphertext
                0,NULL, // aad
                0,NULL, // info
                &clearlen, clear);  // clear
    if (rv!=1) {
        return NULL;
    }
    ech_pbuf("clear",clear,clearlen);
    /*
     * Allocate space for that now, including msg type and 2 octet length
     */
    unsigned char *innerch=OPENSSL_malloc(clearlen);
    if (!innerch) {
        return NULL;
    }
    memcpy(innerch,clear,clearlen);
    *innerlen=clearlen;
    return innerch;
}
/**
 * @brief Decodes inbound ECH extension 
 */
int tls_parse_ctos_ech(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    size_t clearlen=0;
    unsigned char *clear=NULL;
    int assume_grease=0;
    if (s->ech==NULL) {
        printf("tls_parse_ctos_ech called - NULL ECH so assuming grease\n");
        assume_grease=1;
    } else {
        printf("tls_parse_ctos_ech called - with a real ECH!\n");
    }

    /*
     * Decode the inbound value
     * We're looking for:
     *
     * struct {
     *   ECHCipherSuite cipher_suite;
     *   opaque config_id<0..255>;
     *   opaque enc<1..2^16-1>;
     *   opaque payload<1..2^16-1>;
     *  } ClientECH;
     */
    ECH_ENCCH *extval=NULL;

    extval=OPENSSL_malloc(sizeof(ECH_ENCCH));
    if (extval==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (s->ech!=NULL) {
        s->ech->the_ech=extval;
    }

    unsigned int tmp;
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->kdf_id=tmp&0xffff;
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->aead_id=tmp&0xffff;

    /* config id */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > MAX_ECH_CONFIG_ID_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->config_id_len=tmp;
    extval->config_id=OPENSSL_malloc(tmp);
    if (extval->config_id==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, extval->config_id, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /* enc - the client's public share */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > MAX_ECH_ENC_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->enc_len=tmp;
    extval->enc=OPENSSL_malloc(tmp);
    if (extval->enc==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, extval->enc, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /* payload - the encrypted CH */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > MAX_ECH_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->payload_len=tmp;
    extval->payload=OPENSSL_malloc(tmp);
    if (extval->payload==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, extval->payload, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /*
     * Now see which (if any) of our configs match, or whether
     * we need to trial decrypt
     */
    int cfgind=-1;
    int foundcfg=0;
    if (assume_grease==0 && extval->config_id_len!=0) {
        if (s->ech->cfg==NULL || s->ech->cfg->nrecs==0) {
            // shouldn't happen if assume_grease
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
            goto err;
        }
        for (cfgind=0;cfgind!=s->ech->cfg->nrecs;cfgind++) {
            ECHConfig *e=&s->ech[cfgind].cfg->recs[0];
            if (extval->config_id_len==e->config_id_len
                    && !memcmp(extval->config_id,e->config_id,e->config_id_len)) {
                foundcfg=1;
                break;
            }
        }
    }
    /*
     * Trial decrypt
     */
    if (!foundcfg && (s->options & SSL_OP_ECH_TRIALDECRYPT)) { 
        assume_grease=1;
        for (cfgind=0;cfgind!=s->ech->cfg->nrecs;cfgind++) {
            clear=hpke_decrypt_encch(&s->ech[cfgind],&clearlen);
            if (clear!=NULL) {
                foundcfg=1;
                break;
            }
        }
    }
    if (!foundcfg) {
        clear=hpke_decrypt_encch(&s->ech[cfgind],&clearlen);
        if (clear!=NULL) foundcfg=1;
    }
    printf("parse_ctos_ech: assume_grease: %d, foundcfg: %d, cfgind: %d, clearlen: %ld, clear %p\n",
            assume_grease,foundcfg,cfgind,clearlen,clear);
    if (!foundcfg) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /*
     * Clear with a type/len prceeded
     */
    ech_pbuf("clear",clear,clearlen);

    /*
     * Now we would like to re-construct an inner CH from that cleartext
     *
     * Idea is to decode, then check for outers and if we find 'em
     * copy each one from the outer
     */
    PACKET innerpacket;
    if (clearlen < 9) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (PACKET_buf_init(&innerpacket,clear+9,clearlen-9)!=1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /*
     * Stash outer stuff incl SNI, if any (i.e. could be NULL)
     */
    s->clienthello_stash=s->clienthello;
    s->clienthello=NULL;
    /*
     * Might have to zap more in a bit, TODO: check
     */
    s->ext.hostname=NULL;
    s->servername_done=0;
    /*
     * Process inner CH
     */
    s->ext.ch_depth=1;
    if (!tls_process_client_hello(s,&innerpacket)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!s->clienthello || !s->clienthello->pre_proc_exts) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!tls_parse_all_extensions(s, SSL_EXT_CLIENT_HELLO, s->clienthello->pre_proc_exts, NULL, 0,0)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /*
     * Lastly, all having gone well, we should do a swapperoo - ditch the outer and go with the
     * inner
     */

    if (clearlen!=0 && clear!=NULL) {
        OPENSSL_free(clear);
        clear=NULL;
        clearlen=0;
    }
    return 1;

err:
    if (s->ech==NULL && extval!=NULL) {
        ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
    }
    if (clearlen!=0 && clear!=NULL) {
        OPENSSL_free(clear);
    }
    return(0);
}

/**
 * @brief Answer an ECH
 */
EXT_RETURN tls_construct_stoc_ech(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    return EXT_RETURN_NOT_SENT;
}

int tls_parse_ctos_ech_outer_exts(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    /*
     * There better now be one of these in the outer CH
     */
    if (s->ext.ch_depth==0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }
    if (s->ech==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }
    if (s->clienthello_stash==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }
    if (s->clienthello_stash->pre_proc_exts==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }
    /*
     * For each extension here, if there's an outer equivalent, then splice
     * that in, bail if there're errors
     */
    int nouters=PACKET_remaining(pkt)/2;
    printf("We have %d compressed exts\n",nouters);
    if (nouters>=ECH_OUTERS_MAX) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }
    uint16_t *etypes=s->ech->outer_only;
    s->ech->n_outer_only=nouters;
    int exti=0;
    for (exti=0;exti!=nouters;exti++) {
        unsigned int tmp;
        if (!PACKET_get_net_2(pkt, &tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
            return(0);
        }
        etypes[exti]=(uint32_t) (tmp&0xffff);
        printf("\touter %d is type %x\n",exti,etypes[exti]);
    }

    /*
     * Plan is:
     * - splice in the values from outer, but there's a gotcha:
     *    pre_proc_exts has an entry for all known exts that includes
     *    flags for present/parsed/rx'd order so we need to fix those 
     *    values up and get these re-parsed in case there's a side
     *    effect (sigh - this compression is nuts!)
     * - finally check de-compress won't break a rule (e.g. 2 occurrences of one ext type)
     * - declare victory
     */

    /*
     * Figure out the offset of the outers in inner, that'll be what we up positions
     * by
     */
    int outer_order=-1; ///< the order of the outer_ext in the inner CH, we'll splice in exts from outer at this point
    RAW_EXTENSION *inner=s->clienthello->pre_proc_exts;
    int inner_size=s->clienthello->pre_proc_exts_len;
    for (int i=0;i!=inner_size;i++) {
        if (inner->type==TLSEXT_TYPE_outer_extensions && inner->present) {
            outer_order=inner->received_order;
            break;
        }
        inner++;
    }
    if (outer_order==-1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
        return(0);
    }

    /* 
     * Now look through outer CH exts and adjust inners as needed
     * This code depends on the inner and outer RAW_EXTENSION arrays having
     * the same exts at the same indices. So don't change that;-) 
     * We do do some checks just in case.
     */
    const RAW_EXTENSION *outer=s->clienthello_stash->pre_proc_exts;
    inner=s->clienthello->pre_proc_exts;
    int outer_size=s->clienthello_stash->pre_proc_exts_len;
    if (inner_size!=outer_size) return(0);
    for (int i=0;i!=outer_size;i++) {
        if (inner->present==1 && inner->type!= TLSEXT_TYPE_outer_extensions && inner->type!=outer->type) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PARSE_CTOS_ECH_OUTER_EXTS, SSL_R_BAD_EXTENSION);
            return(0);
        }
        for (int j=0;j!=nouters;j++) {
            if (outer->type==etypes[j] && outer->present==1) {
                printf("Compressed Ext %d (type %x) is present in outer CH (pos %d, rx pos %ld, parsed: %d, size: %ld)\n",
                        j,etypes[j],i,outer->received_order,outer->parsed,outer->data.remaining);
                if (inner->present==1 && inner->received_order>=outer_order) {
                    inner->received_order=outer_order+j;
                }
                /*
                 * TODO: FIXME: this is broken - by the time we're here, outer->data
                 * has been parsed which means that the PACKET has zero data remaining
                 * so if we re-parsed it, we'd fail. However, we should also be luck
                 * in that the SSL *s input here starts out with the result of having
                 * done that parsing, so we should be ok, unless there's some interaction
                 * between yet another extension value and "this" one where we have
                 * different values for "this" one in inner and outer.
                 * Yes, this compression sucks awfully.
                 * Oh - and the packet data pointer is probably gonna cause trouble
                 * when freed (but we'll see that soon)
                 */
                inner->data=outer->data;
            }
        }
        outer++; inner++;
    }
    return 1;
}

EXT_RETURN tls_construct_stoc_ech_outer_exts(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    return EXT_RETURN_NOT_SENT;
}

#endif // END_OPENSSL_NO_ECH
// ESNI_DOXY_END
