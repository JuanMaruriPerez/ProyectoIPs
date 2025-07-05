#include "crypto_utils.h"
#include <stdio.h>
#include <string.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>

// ---------- Inicialización ----------
int crypto_init() {
    // Cargar el proveedor default + oqs
    if (!OSSL_PROVIDER_load(NULL, "default")) {
        fprintf(stderr, "Error cargando provider default\n");
        return 0;
    }
    if (!OSSL_PROVIDER_load(NULL, "oqsprovider")) {
        fprintf(stderr, "Error cargando oqsprovider\n");
        return 0;
    }
    return 1;
}

void crypto_cleanup() {
    // No es estrictamente necesario en la mayoría de contextos
    // pero puedes añadir OSSL_PROVIDER_unload si haces unload manual
}

// ---------- Generación de claves ----------
EVP_PKEY *generate_key(const char *alg_name) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Error inicializando generación para %s\n", alg_name);
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error generando clave %s\n", alg_name);
        pkey = NULL;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *generate_ecdh_key(const char *alg) {
    return generate_key(alg);
}

EVP_PKEY *generate_kem_key(const char *alg) {
    return generate_key(alg);
}

// ---------- Derivación de secreto ECDH ----------
int derive_ecdh_secret(EVP_PKEY *privkey, EVP_PKEY *peerkey, uint8_t *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0 ||
        EVP_PKEY_derive(ctx, NULL, secret_len) <= 0 ||
        EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        fprintf(stderr, "Error derivando secreto ECDH\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// ---------- KEM ----------
int kem_encapsulate(EVP_PKEY *pub, uint8_t *ciphertext, size_t *ct_len, uint8_t *shared_secret, size_t *ss_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(ctx, ciphertext, ct_len, shared_secret, ss_len) <= 0) {
        fprintf(stderr, "Error en encapsulación KEM\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int kem_decapsulate(EVP_PKEY *priv, const uint8_t *ct, size_t ct_len, uint8_t *shared_secret, size_t *ss_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(ctx, shared_secret, ss_len, ct, ct_len) <= 0) {
        fprintf(stderr, "Error en decapsulación KEM\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// ---------- HKDF ----------
int hkdf_derive(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len, const char *hash_alg) {
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        fprintf(stderr, "Error obteniendo HKDF\n");
        return 0;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", (char *)hash_alg, 0),
        OSSL_PARAM_octet_string("salt", "", 0),
        OSSL_PARAM_octet_string("key", input, input_len),
        OSSL_PARAM_octet_string("info", "handshake key", strlen("handshake key")),
        OSSL_PARAM_END
    };

    if (EVP_KDF_derive(kctx, output, output_len, params) <= 0) {
        fprintf(stderr, "Error en derivación HKDF\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

// ---------- Serialización ----------
int serialize_pubkey(EVP_PKEY *key, uint8_t *out, size_t *out_len) {
    return EVP_PKEY_get_raw_public_key(key, out, out_len) > 0;
}

EVP_PKEY *deserialize_pubkey(const char *alg_name, const uint8_t *in, size_t in_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0) {
        fprintf(stderr, "Error creando contexto para %s\n", alg_name);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    params[0] = OSSL_PARAM_construct_octet_string("pub", (void *)in, in_len);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        fprintf(stderr, "Error reconstruyendo clave pública %s\n", alg_name);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


// ---------- Debug ----------
void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}
