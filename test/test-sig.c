#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("ML-DSA 独立测试程序\n");
    printf("===================\n\n");

    OQS_init();

    const char* algorithms[] = {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        NULL
    };

    for (int i = 0; algorithms[i] != NULL; i++) {
        const char* alg = algorithms[i];

        printf("\n测试算法: %s\n", alg);
        printf("------------------------\n");

        if (!OQS_SIG_alg_is_enabled(alg)) {
            printf("❌ 算法未启用\n");
            continue;
        }

        OQS_SIG* sig = OQS_SIG_new(alg);
        if (!sig) {
            printf("❌ 无法创建签名实例\n");
            continue;
        }

        // 分配内存
        uint8_t* public_key = malloc(sig->length_public_key);
        uint8_t* secret_key = malloc(sig->length_secret_key);
        uint8_t* signature = malloc(sig->length_signature);

        if (!public_key || !secret_key || !signature) {
            printf("❌ 内存分配失败\n");
            OQS_SIG_free(sig);
            continue;
        }

        // 生成密钥对
        if (OQS_SIG_keypair(sig, public_key, secret_key) == OQS_SUCCESS) {
            printf("✅ 密钥对生成成功\n");
        } else {
            printf("❌ 密钥对生成失败\n");
        }

        // 准备消息
        const char* message = "测试消息";
        size_t message_len = strlen(message);
        size_t signature_len = 0;

        // 签名
        if (OQS_SIG_sign(sig, signature, &signature_len,
                        (const uint8_t*)message, message_len, secret_key) == OQS_SUCCESS) {
            printf("✅ 签名成功 (长度: %zu 字节)\n", signature_len);
        } else {
            printf("❌ 签名失败\n");
        }

        // 验证
        OQS_STATUS verify_status = OQS_SIG_verify(sig,
            (const uint8_t*)message, message_len,
            signature, signature_len, public_key);

        if (verify_status == OQS_SUCCESS) {
            printf("✅ 签名验证成功\n");
        } else {
            printf("❌ 签名验证失败\n");
        }

        // 清理
        free(public_key);
        free(secret_key);
        free(signature);
        OQS_SIG_free(sig);
    }

    return 0;
}