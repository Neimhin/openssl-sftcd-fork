/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal data structures and prototypes for handling
 * stealthy Encrypted ClientHello (SECH)
 */
#ifndef OPENSSL_H_SECH_HELPERS
#define OPENSSL_H_SECH_HELPERS
#ifndef OPENSSL_NO_SECH
#define SECH_SYMMETRIC_KEY_MAX_LENGTH 1024
char * unsafe_encrypt_aes128gcm(
    unsigned char * plain,
    int plain_len,
    unsigned char iv[12],
    unsigned char * somekey,
    int key_len,
    int * out_len);
char *unsafe_decrypt_aes128gcm(
    unsigned char *ciphertext,
    int ciphertext_len,
    unsigned char iv[12],
    unsigned char *somekey,
    int key_len,
    int *out_len);
#endif
#endif
