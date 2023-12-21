// Comment out to use EVP_KDF_derive() instead of own implementation
#define USE_OWN_IOMPLEMENTATION

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#ifndef USE_OWN_IOMPLEMENTATION
#include <openssl/kdf.h>
#endif
#include <openssl/hmac.h>

/*
{
    "vsId": 1,
    "algorithm": "kdf-components",
    "mode": "tls",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "hashAlg": "SHA-1",
            "tlsVersion": "v1.0/1.1",
            "keyBlockLength": 128,
            "preMasterSecretLength": 96,
            "testType": "AFT",
            "tests": [
                {
                    "tcId": 1,
                    "preMasterSecret": "E500EB713ECDDE15EEDD4890E20A7CB387DFB9E0469E3CBDC6E339D320787A8AB02B6A99485812A7DCF935C1426692CB",
                    "clientHelloRandom": "D255A56BF40A899D411F485F1C95D133EEFCB29784859FAE914F2DF79CB1EEF9",
                    "serverHelloRandom": "08265B226DFF6FCFB185E4559F0BDFE1625759C3F134782C86904208F14DB93C",
                    "clientRandom": "D163224298229C33577CB59A8C12A832437E2E13E6EF0F41F1E50B65DD48B34A",
                    "serverRandom": "1EAE4DE8C9AAF036946E9A487A3BBBF0A09D9EF5465E19F9D6FD79100FA62B52"

                }
            ]
        }
    ]
}

Expected result values:
"tcId": 1,
"masterSecret": "E6F103748D56156E76FA96B70D586485E9A7320ACE0C85112F8F89BEA0860E3ED2F42EE499BF99A0BD8B1AF5C2205903",
"keyBlock": "3DFF6187CF399E0E0EBA9646970275E3D045136F3C3BA5A242ED9F351F1E0F6E510517B476C0F219FB640A9874911CBB96BC17AC9484BE521987B1E3276E3307ED460C593D8D098DBB5D080D920733E0A6C37837E71B3A5AACB39E9F50110F633B2B93FEF1799E1705E2765ECF95571CDF2A3D3A1B6C0997A9682781297D255C"
*/

#define SHA_224_SIZE 28
#define SHA_256_SIZE 32
#define SHA_384_SIZE 48
#define SHA_512_SIZE 64

char *bin2hex(const uint8_t *bin, size_t bin_size) {
    char *hex;
    size_t i;

    hex = malloc(bin_size * 2 + 1);
    for (i = 0; i < bin_size; i++) {
        sprintf(&hex[i * 2], "%02X", bin[i]);
    }
    hex[i * 2] = '\0';

    return hex;
}

/**
 * Convert hexadecimal string into bytes.
 */
static bool hex2bin(const char *hex,
                    uint8_t *data,
                    size_t datalen) {
    size_t i;
    size_t hexlen = strlen(hex);

    if (hexlen < datalen * 2) {
        fprintf(stderr, "Invalid hex length\n");
        return false;
    }

    for (i = 0; i < datalen; i++) {
        if (hex[0] >= '0' && hex[0] <= '9') {
            data[i] = (uint8_t)(hex[0] - '0') << 4;
        } else if (hex[0] >= 'a' && hex[0] <= 'f') {
            data[i] = (uint8_t)(hex[0] - 'a' + 10) << 4;
        } else if (hex[0] >= 'A' && hex[0] <= 'F') {
            data[i] = (uint8_t)(hex[0] - 'A' + 10) << 4;
        } else {
            return false;
        }

        if (hex[1] >= '0' && hex[1] <= '9') {
            data[i] |= (uint8_t)(hex[1] - '0');
        } else if (hex[1] >= 'a' && hex[1] <= 'f') {
            data[i] |= (uint8_t)(hex[1] - 'a' + 10);
        } else if (hex[1] >= 'A' && hex[1] <= 'F') {
            data[i] |= (uint8_t)(hex[1] - 'A' + 10);
        } else {
            return false;
        }

        hex += 2;
    }

    return true;
}

#ifndef USE_OWN_IOMPLEMENTATION
bool p_hash(const char *hash_alg,
            const char *tls_ver,
            uint8_t *secret_data,
            size_t secret_data_size,
            const uint8_t *label_data,
            size_t label_data_size,
            const uint8_t *seed_data,
            size_t seed_data_size,
            uint8_t *out,
            size_t out_size) {
    bool ret = false;
    uint8_t *label_and_seed_data = NULL;
    size_t label_and_seed_data_size;
    char *kdf_hash_alg;
    char *kdf_tls_ver;
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;

    // Concat label and seed
    label_and_seed_data_size = label_data_size + seed_data_size;
    label_and_seed_data = calloc(1, label_and_seed_data_size);
    memcpy(label_and_seed_data, label_data, label_data_size);
    memcpy(&label_and_seed_data[label_data_size], seed_data, seed_data_size);

    if (strcmp(hash_alg, "SHA-256") == 0) {
        kdf_hash_alg = SN_sha256;
    } else {
        fprintf(stderr, "Invalid hash algo\n");
        goto cleanup;
    }

    if (strcmp(tls_ver, "v1.0/1.1") == 0) {
        kdf_tls_ver = "TLS1-PRF";
    } else {
        fprintf(stderr, "Invalid TLS version\n");
        goto cleanup;
    }


    kdf = EVP_KDF_fetch(NULL, kdf_tls_ver, NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            kdf_hash_alg,
                                            strlen(kdf_hash_alg));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                             secret_data,
                                             secret_data_size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
                                             label_and_seed_data,
                                             label_and_seed_data_size);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, out_size, params) <= 0) {
        fprintf(stderr, "EVP_KDF_derive");
        goto cleanup;
    }

    ret = true;

cleanup:
    free(label_and_seed_data);
    EVP_KDF_CTX_free(kctx);

    return ret;
}

#else
__attribute__((unused))
bool p_hash(const char *hash_alg,
            const char *tls_ver,
            uint8_t *secret_data,
            size_t secret_data_size,
            const uint8_t *label_data,
            size_t label_data_size,
            const uint8_t *seed_data,
            size_t seed_data_size,
            uint8_t *out,
            size_t out_size) {
/*
https://www.rfc-editor.org/rfc/rfc5246#section-5

PRF(secret, label, seed) = P_<hash>(secret, label + seed)


P_hash(secret, label_and_seed) = HMAC_hash(secret, A(1) + label_and_seed) +
                       HMAC_hash(secret, A(2) + label_and_seed) +
                       HMAC_hash(secret, A(3) + label_and_seed) + ...

A() is defined as:
A(0) = label_and_seed
A(i) = HMAC_hash(secret, A(i-1))
*/
    bool ret = false;
    size_t iterations = 0;
    const EVP_MD *kdf_hash_md;
    size_t kdf_hash_size;
    uint8_t *label_and_seed_data = NULL;
    size_t label_and_seed_data_size;
    uint8_t A[EVP_MAX_MD_SIZE * 3] = { 0 }; // needs to be bigger than a MD
    size_t A_size;
    uint8_t P_hash[EVP_MAX_MD_SIZE] = { 0 };
    size_t P_hash_size = sizeof(P_hash);
    uint8_t *out_buff = NULL;
    size_t out_buff_size;
    size_t out_buff_used_size = 0;

    (void)tls_ver;

    if (strcmp(hash_alg, "SHA-256") == 0) {
        kdf_hash_size = SHA_256_SIZE;
        kdf_hash_md = EVP_sha256();
    } else if (strcmp(hash_alg, "SHA-224") == 0) {
        kdf_hash_size = SHA_224_SIZE;
        kdf_hash_md = EVP_sha224();
    } else if (strcmp(hash_alg, "SHA-384") == 0) {
        kdf_hash_size = SHA_384_SIZE;
        kdf_hash_md = EVP_sha384();
    } else if (strcmp(hash_alg, "SHA-512") == 0) {
        kdf_hash_size = SHA_512_SIZE;
        kdf_hash_md = EVP_sha512();
    } else {
        fprintf(stderr, "Invalid hash algo\n");
        goto cleanup;
    }


    // Allocate results buffer (for digest sha256)
    iterations = out_size / kdf_hash_size;
    if (out_size % kdf_hash_size > 0) {
        iterations++;
    }
    out_buff_size = iterations * kdf_hash_size;
    out_buff = calloc(1, out_buff_size);

    // Concat label and seed
    label_and_seed_data_size = label_data_size + seed_data_size;
    label_and_seed_data = calloc(1, label_and_seed_data_size);
    memcpy(label_and_seed_data, label_data, label_data_size);
    memcpy(&label_and_seed_data[label_data_size], seed_data, seed_data_size);

    // Set initial A to label_and_seed
    memcpy(A, label_and_seed_data, label_and_seed_data_size);
    A_size = label_and_seed_data_size;

    for (int i = 0; i < iterations; i++) {
        uint8_t new_A[EVP_MAX_MD_SIZE] = { 0 };
        size_t new_A_size = sizeof(new_A);
        uint8_t A_label_seed[EVP_MAX_MD_SIZE * 6] = { 0 }; // Need more space
        size_t A_label_seed_size;

        // Get new A
        if (HMAC(kdf_hash_md, secret_data, (int)secret_data_size,
                 A, (int)A_size, new_A,
                 (unsigned int *)&new_A_size) == NULL) {
            fprintf(stderr, "%s() 'A' failed\n", __func__);
            goto cleanup;
        }

        // Set new A to be old A now after we have used the old A
        memcpy(A, new_A, new_A_size);
        A_size = new_A_size;
        memcpy(A_label_seed, new_A, new_A_size);
        A_label_seed_size = new_A_size;

        // And append the label_and_seed to A
        memcpy(&A_label_seed[A_label_seed_size],
               label_and_seed_data,
               label_and_seed_data_size);
        A_label_seed_size += label_and_seed_data_size;

        // Get new P_hash
        if (HMAC(kdf_hash_md, secret_data, (int)secret_data_size, A_label_seed,
                 (int)A_label_seed_size, P_hash,
                 (unsigned int *)&P_hash_size) == NULL) {
            fprintf(stderr, "%s(): 'P_hash' failed\n", __func__);
            goto cleanup;
        }

        char *tmp = bin2hex(P_hash, P_hash_size);
        free(tmp);

        if (out_buff_size < out_buff_used_size + P_hash_size) {
            fprintf(stderr, "%s(): No space left for generating MD\n", __func__);
            goto cleanup;
        }
        memcpy(&out_buff[out_buff_used_size], P_hash, P_hash_size);
        out_buff_used_size += P_hash_size;
    }

    memcpy(out, out_buff, out_size);

    ret = true;

cleanup:
    free(label_and_seed_data);
    free(out_buff);

    return ret;
}
#endif

bool gen_master_secret(const char *hash_alg,
                       const char *tls_ver,
                       uint8_t *pre_master_secret,
                       size_t pre_master_secret_size,
                       const uint8_t *client_hello_rand,
                       size_t client_hello_rand_size,
                       const uint8_t *server_hello_rand,
                       size_t server_hello_rand_size,
                       uint8_t *master_secret,
                       size_t master_secret_size) {
/*
https://www.rfc-editor.org/rfc/rfc5246#section-8.1

master_secret = PRF(pre_master_secret, "master secret",
                    ClientHello.random + ServerHello.random)
                          [0..47];
*/
    bool ret = false;
    uint8_t *hello_rand = NULL;
    size_t hello_rand_size;

    hello_rand_size = client_hello_rand_size + server_hello_rand_size;
    hello_rand = calloc(1, hello_rand_size);
    memcpy(hello_rand,
           client_hello_rand,
           client_hello_rand_size);
    memcpy(&hello_rand[client_hello_rand_size],
           server_hello_rand,
           server_hello_rand_size);

    if (!p_hash(hash_alg,
                tls_ver,
                pre_master_secret,
                pre_master_secret_size,
                (uint8_t *)"master secret",
                strlen("master secret"),
                hello_rand,
                hello_rand_size,
                master_secret,
                master_secret_size)) {
        goto cleanup;
    }

    ret = true;

cleanup:
    free(hello_rand);

    return ret;
}

bool gen_key_block(const char *hash_alg,
                   const char *tls_ver,
                   uint8_t *master_secret,
                   size_t master_secret_size,
                   const uint8_t *server_rand,
                   size_t server_rand_size,
                   const uint8_t *client_rand,
                   size_t client_rand_size,
                   uint8_t *key_block,
                   size_t key_block_size) {
/*
https://www.rfc-editor.org/rfc/rfc5246#section-6.3

key_block = PRF(SecurityParameters.master_secret,
                "key expansion",
                SecurityParameters.server_random +
                SecurityParameters.client_random);
*/
    bool ret = false;
    uint8_t *concat_rand = NULL;
    size_t concat_rand_size;

    concat_rand_size = server_rand_size + client_rand_size;
    concat_rand = calloc(1, concat_rand_size);
    memcpy(concat_rand,
           server_rand,
           server_rand_size);
    memcpy(&concat_rand[server_rand_size],
           client_rand,
           client_rand_size);

    if (!p_hash(hash_alg,
                tls_ver,
                master_secret,
                master_secret_size,
                (uint8_t *)"key expansion",
                strlen("key expansion"),
                concat_rand,
                concat_rand_size,
                key_block,
                key_block_size)) {
        goto cleanup;
    }

    ret = true;

cleanup:
    free(concat_rand);

    return ret;
}

int main(void) {
/*
"hashAlg": "SHA-256",
"tlsVersion": "v1.0/1.1",
"keyBlockLength": 128,
"preMasterSecretLength": 96,
*/

    // Input values coming from the ACVP test
    char *hash_alg = "SHA-256";
    char *tls_ver = "v1.0/1.1";
    const char *pre_master_secret_hex = "E500EB713ECDDE15EEDD4890E20A7CB387DFB9E0469E3CBDC6E339D320787A8AB02B6A99485812A7DCF935C1426692CB";
    const char *client_hello_random_hex = "D255A56BF40A899D411F485F1C95D133EEFCB29784859FAE914F2DF79CB1EEF9";
    const char *server_hello_random_hex = "08265B226DFF6FCFB185E4559F0BDFE1625759C3F134782C86904208F14DB93C";
    const char *client_random_hex = "D163224298229C33577CB59A8C12A832437E2E13E6EF0F41F1E50B65DD48B34A";
    const char *server_random_hex = "1EAE4DE8C9AAF036946E9A487A3BBBF0A09D9EF5465E19F9D6FD79100FA62B52";
    const char *expected_master_key_hex = "E6F103748D56156E76FA96B70D586485E9A7320ACE0C85112F8F89BEA0860E3ED2F42EE499BF99A0BD8B1AF5C2205903";
    const char *expected_key_block_hex = "3DFF6187CF399E0E0EBA9646970275E3D045136F3C3BA5A242ED9F351F1E0F6E510517B476C0F219FB640A9874911CBB96BC17AC9484BE521987B1E3276E3307ED460C593D8D098DBB5D080D920733E0A6C37837E71B3A5AACB39E9F50110F633B2B93FEF1799E1705E2765ECF95571CDF2A3D3A1B6C0997A9682781297D255C";

    int ret = EXIT_FAILURE;
    uint8_t master_secret[48] = { 0 };
    size_t master_secret_size = sizeof(master_secret);
    size_t key_block_size = 128;
    uint8_t *key_block = NULL;
    char *hex_data = NULL;
    uint8_t *pre_master_secret = NULL;
    uint8_t *client_hello_random = NULL;
    uint8_t *server_hello_random = NULL;
    uint8_t *client_random = NULL;
    uint8_t *server_random = NULL;
    size_t pre_master_secret_size;
    size_t client_hello_random_size;
    size_t server_hello_random_size;
    size_t client_random_size;
    size_t server_random_size;

    pre_master_secret_size = strlen(pre_master_secret_hex) / 2;
    pre_master_secret = calloc(1, pre_master_secret_size);

    client_hello_random_size = strlen(client_hello_random_hex) / 2;
    client_hello_random = calloc(1, client_hello_random_size);

    server_hello_random_size = strlen(server_hello_random_hex) / 2;
    server_hello_random = calloc(1, server_hello_random_size);

    client_random_size = strlen(client_random_hex) / 2;
    client_random = calloc(1, client_random_size);

    server_random_size = strlen(server_random_hex) / 2;
    server_random = calloc(1, server_random_size);

    // Convert from hexadecimal to usable bytes
    if (!hex2bin(pre_master_secret_hex,
                 pre_master_secret,
                 pre_master_secret_size)) {
        fprintf(stderr, "Failed to decode hex string to binary\n");
        goto cleanup;
    }

    if (!hex2bin(client_hello_random_hex,
                 client_hello_random,
                 client_hello_random_size)) {
        fprintf(stderr, "Failed to decode hex string to binary\n");
        goto cleanup;
    }

    if (!hex2bin(server_hello_random_hex,
                 server_hello_random,
                 server_hello_random_size)) {
        fprintf(stderr, "Failed to decode hex string to binary\n");
        goto cleanup;
    }

    if (!hex2bin(server_random_hex,
                 server_random,
                 server_random_size)) {
        fprintf(stderr, "Failed to decode hex string to binary\n");
        goto cleanup;
    }

    if (!hex2bin(client_random_hex,
                 client_random,
                 client_random_size)) {
        fprintf(stderr, "Failed to decode hex string to binary\n");
        goto cleanup;
    }

    key_block = calloc(1, key_block_size);

    // Calculate Key Master Key
    if (!gen_master_secret(hash_alg,
                           tls_ver,
                           pre_master_secret,
                           pre_master_secret_size,
                           client_hello_random,
                           client_hello_random_size,
                           server_hello_random,
                           server_hello_random_size,
                           master_secret,
                           master_secret_size)) {
        goto cleanup;
    }

    // Calculate Key Block
    if (!gen_key_block(hash_alg,
                       tls_ver,
                       master_secret,
                       master_secret_size,
                       server_random,
                       server_random_size,
                       client_random,
                       client_random_size,
                       key_block,
                       key_block_size)) {
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

    // Print calculated master key
    hex_data = bin2hex(master_secret, master_secret_size);
    if (strcmp(hex_data, expected_master_key_hex) != 0) {
        fprintf(stderr, "Generated master secret is not as expected\n");
        fprintf(stderr, "calculated master key:  %s\n", hex_data);
        fprintf(stderr, "expected master secret: %s\n", expected_master_key_hex);
        goto cleanup;
    }
    free(hex_data);

    // Print calculated key block
    hex_data = bin2hex(key_block, key_block_size);
    if (strcmp(hex_data, expected_key_block_hex) != 0) {
        fprintf(stderr, "Generated key block is not as expected\n");
        fprintf(stderr, "calculated key block: %s\n", hex_data);
        fprintf(stderr, "expected key block:   %s\n", expected_key_block_hex);
        goto cleanup;
    }

    printf("Success!\n");

cleanup:
    free(hex_data);
    free(key_block);
    free(pre_master_secret);
    free(client_hello_random);
    free(server_hello_random);
    free(client_random);
    free(server_random);

    return ret;
}
