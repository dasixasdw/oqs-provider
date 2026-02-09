
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("ML-KEM 独立测试程序\n");
    printf("===================\n\n");
    
    OQS_init();
    
    const char* algorithms[] = {
        "ML-KEM-512",
        "ML-KEM-768", 
        "ML-KEM-1024",
        NULL
    };
    
    for (int i = 0; algorithms[i] != NULL; i++) {
        const char* alg = algorithms[i];
        
        printf("\n测试算法: %s\n", alg);
        printf("------------------------\n");
        
        if (!OQS_KEM_alg_is_enabled(alg)) {
            printf("❌ 算法未启用\n");
            continue;
        }
        
        OQS_KEM* kem = OQS_KEM_new(alg);
        if (!kem) {
            printf("❌ 无法创建 KEM 实例\n");
            continue;
        }
        
        // 分配内存
        uint8_t* public_key = malloc(kem->length_public_key);
        uint8_t* secret_key = malloc(kem->length_secret_key);
        uint8_t* ciphertext = malloc(kem->length_ciphertext);
        uint8_t* shared_secret_e = malloc(kem->length_shared_secret);
        uint8_t* shared_secret_d = malloc(kem->length_shared_secret);
        
        if (!public_key || !secret_key || !ciphertext || 
            !shared_secret_e || !shared_secret_d) {
            printf("❌ 内存分配失败\n");
            OQS_KEM_free(kem);
            continue;
        }
        
        // 生成密钥对
        if (kem->keypair(public_key, secret_key) == OQS_SUCCESS) {
            printf("✅ 密钥对生成成功\n");
        } else {
            printf("❌ 密钥对生成失败\n");
        }
        
        // 封装
        if (kem->encaps(ciphertext, shared_secret_e, public_key) == OQS_SUCCESS) {
            printf("✅ 封装成功\n");
        } else {
            printf("❌ 封装失败\n");
        }
        
        // 解封装
        if (kem->decaps(shared_secret_d, ciphertext, secret_key) == OQS_SUCCESS) {
            printf("✅ 解封装成功\n");
        } else {
            printf("❌ 解封装失败\n");
        }
        
        // 验证
        if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
            printf("✅ 共享密钥验证成功\n");
        } else {
            printf("❌ 共享密钥不匹配\n");
        }
        
        // 清理
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(shared_secret_e);
        free(shared_secret_d);
        OQS_KEM_free(kem);
    }

    return 0;
}