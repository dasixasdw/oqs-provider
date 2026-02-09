#include "oqs-provider.h"
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 测试 ML-KEM
void test_ml_kem(const char *alg_name) {
    printf("\n=== 测试 %s ===\n", alg_name);

    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        printf("❌ 算法未启用\n");
        return;
    }

    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        printf("❌ 无法创建 KEM 实例\n");
        return;
    }

    printf("✅ 算法信息:\n");
    printf("   公钥长度: %zu 字节\n", kem->length_public_key);
    printf("   私钥长度: %zu 字节\n", kem->length_secret_key);
    printf("   密文长度: %zu 字节\n", kem->length_ciphertext);
    printf("   共享密钥长度: %zu 字节\n", kem->length_shared_secret);

    // 分配内存
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_e || !shared_secret_d) {
        printf("❌ 内存分配失败\n");
        goto cleanup;
    }

    // 1. 生成密钥对
    if (kem->keypair(public_key, secret_key) != OQS_SUCCESS) {
        printf("❌ 密钥对生成失败\n");
        goto cleanup;
    }
    printf("✅ 密钥对生成成功\n");

    // 2. 封装
    if (kem->encaps(ciphertext, shared_secret_e, public_key) != OQS_SUCCESS) {
        printf("❌ 封装失败\n");
        goto cleanup;
    }
    printf("✅ 封装成功\n");

    // 3. 解封装
    if (kem->decaps(shared_secret_d, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("❌ 解封装失败\n");
        goto cleanup;
    }
    printf("✅ 解封装成功\n");

    // 4. 验证共享密钥
    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
        printf("✅ 共享密钥验证成功\n");

        // 打印前16字节
        printf("共享密钥 (前16字节): ");
        for (int i = 0; i < 16 && i < kem->length_shared_secret; i++) {
            printf("%02x", shared_secret_e[i]);
        }
        printf("\n");
    } else {
        printf("❌ 共享密钥不匹配\n");
    }

cleanup:
    if (public_key) free(public_key);
    if (secret_key) free(secret_key);
    if (ciphertext) free(ciphertext);
    if (shared_secret_e) free(shared_secret_e);
    if (shared_secret_d) free(shared_secret_d);

    OQS_KEM_free(kem);
}

// 测试 ML-DSA
void test_ml_dsa(const char *alg_name) {
    printf("\n=== 测试 %s ===\n", alg_name);

    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        printf("❌ 算法未启用\n");
        return;
    }

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        printf("❌ 无法创建签名实例\n");
        return;
    }

    printf("✅ 算法信息:\n");
    printf("   公钥长度: %zu 字节\n", sig->length_public_key);
    printf("   私钥长度: %zu 字节\n", sig->length_secret_key);
    printf("   签名最大长度: %zu 字节\n", sig->length_signature);

    // 分配内存
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        printf("❌ 内存分配失败\n");
        goto cleanup;
    }

    // 1. 生成密钥对
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("❌ 密钥对生成失败\n");
        goto cleanup;
    }
    printf("✅ 密钥对生成成功\n");

    // 2. 准备消息
    const char *message = "这是一条测试ML-DSA签名的消息";
    size_t message_len = strlen(message);
    size_t signature_len = 0;

    printf("消息: \"%s\"\n", message);
    printf("消息长度: %zu 字节\n", message_len);

    // 3. 签名
    if (OQS_SIG_sign(sig, signature, &signature_len,
                    (const uint8_t *)message, message_len, secret_key) != OQS_SUCCESS) {
        printf("❌ 签名失败\n");
        goto cleanup;
    }
    printf("✅ 签名成功 (长度: %zu 字节)\n", signature_len);

    // 4. 验证
    OQS_STATUS verify_status = OQS_SIG_verify(sig, (const uint8_t *)message, message_len,
                                             signature, signature_len, public_key);
    if (verify_status == OQS_SUCCESS) {
        printf("✅ 签名验证成功\n");

        // 打印签名摘要
        printf("签名 (前16字节): ");
        for (int i = 0; i < 16 && i < signature_len; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    } else {
        printf("❌ 签名验证失败\n");
    }

cleanup:
    if (public_key) free(public_key);
    if (secret_key) free(secret_key);
    if (signature) free(signature);

    OQS_SIG_free(sig);
}

int main() {
    printf("========================================\n");
    printf("OQS Provider 测试程序\n");
    printf("版本: %s\n", OQS_PROVIDER_VERSION);
    printf("========================================\n\n");

    // 初始化 liboqs
    OQS_init();

    // 测试 ML-KEM 算法
    printf("\n🔐 测试 ML-KEM 算法:\n");
    printf("===================\n");

    test_ml_kem(OQS_ALG_MLKEM512);
    test_ml_kem(OQS_ALG_MLKEM768);
    test_ml_kem(OQS_ALG_MLKEM1024);

    // 测试 ML-DSA 算法
    printf("\n📝 测试 ML-DSA 算法:\n");
    printf("===================\n");

    test_ml_dsa(OQS_ALG_MLDSA44);
    test_ml_dsa(OQS_ALG_MLDSA65);
    test_ml_dsa(OQS_ALG_MLDSA87);

    printf("\n========================================\n");
    printf("所有测试完成\n");
    printf("========================================\n");

    return 0;
}