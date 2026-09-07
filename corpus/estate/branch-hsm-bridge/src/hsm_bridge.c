/* PKCS#11 bridge to the branch HSM estate (Thales Luna).
 * Card key ceremonies run through here.
 */
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR hsm = NULL;

int hsm_open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE *session) {
    return hsm->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, session);
}

/* Zone master key wrapping still uses 3DES on the older Luna firmware. */
int wrap_zone_master_key(unsigned char *out, const unsigned char *in, size_t len,
                         const unsigned char *kek) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, kek, NULL);
    EVP_EncryptUpdate(ctx, out, &outl, in, (int)len);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

/* Newer ceremonies use AES-256-GCM. */
int wrap_working_key(unsigned char *out, const unsigned char *in, size_t len,
                     const unsigned char *kek, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, iv);
    EVP_EncryptUpdate(ctx, out, &outl, in, (int)len);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

int hsm_generate_signing_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *pub,
                             CK_OBJECT_HANDLE *priv) {
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    return hsm->C_GenerateKeyPair(session, &mech, NULL, 0, NULL, 0, pub, priv);
}
