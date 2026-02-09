#include "oqs-provider.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// KEM 上下文结构
typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
} oqs_kem_ctx;

// 创建 KEM 上下文
void *oqs_kem_newctx(void *provctx, const char *propq) {
    (void)provctx;
    (void)propq;
    
    oqs_kem_ctx *ctx = calloc(1, sizeof(oqs_kem_ctx));
    if (!ctx) {
        return NULL;
    }
    
    return ctx;
}

// 释放 KEM 上下文
void oqs_kem_freectx(void *vctx) {
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return;
    }
    
    if (ctx->kem) {
        OQS_KEM_free(ctx->kem);
    }
    
    if (ctx->public_key) {
        free(ctx->public_key);
    }
    
    if (ctx->secret_key) {
        free(ctx->secret_key);
    }
    
    free(ctx);
}

// 初始化 KEM
int oqs_kem_init(void *vctx, OSSL_PARAM params[]) {
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return 0;
    }
    
    // 查找算法名称
    const char *alg_name = NULL;
    OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "algorithm");
    if (!p) {
        p = OSSL_PARAM_locate_const(params, "group");
    }
    
    if (p && p->data_type == OSSL_PARAM_UTF8_STRING) {
        alg_name = (const char *)p->data;
    }
    
    if (!alg_name) {
        return 0;
    }
    
    // 检查算法是否启用
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        fprintf(stderr, "KEM 算法 %s 未启用\n", alg_name);
        return 0;
    }
    
    // 创建 KEM 实例
    ctx->kem = OQS_KEM_new(alg_name);
    if (!ctx->kem) {
        fprintf(stderr, "无法创建 KEM 实例: %s\n", alg_name);
        return 0;
    }
    
    return 1;
}

// 生成密钥对
int oqs_kem_keygen(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb;
    (void)cbarg;
    
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx || !ctx->kem) {
        return 0;
    }
    
    // 分配密钥缓冲区
    ctx->public_key = malloc(ctx->kem->length_public_key);
    ctx->secret_key = malloc(ctx->kem->length_secret_key);
    
    if (!ctx->public_key || !ctx->secret_key) {
        if (ctx->public_key) free(ctx->public_key);
        if (ctx->secret_key) free(ctx->secret_key);
        return 0;
    }
    
    ctx->public_key_len = ctx->kem->length_public_key;
    ctx->secret_key_len = ctx->kem->length_secret_key;
    
    // 生成密钥对
    OQS_STATUS rc = ctx->kem->keypair(ctx->public_key, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "KEM 密钥对生成失败\n");
        return 0;
    }
    
    printf("KEM 密钥对生成成功: %zu 字节公钥, %zu 字节私钥\n",
           ctx->public_key_len, ctx->secret_key_len);
    
    return 1;
}

// 封装
int oqs_kem_encapsulate(void *vctx, unsigned char *ct, size_t *ctlen,
                       size_t ctmax, unsigned char *ss, size_t *sslen,
                       size_t ssmax) {
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx || !ctx->kem || !ctx->public_key) {
        return 0;
    }
    
    // 检查缓冲区大小
    if (ctmax < ctx->kem->length_ciphertext ||
        ssmax < ctx->kem->length_shared_secret) {
        return 0;
    }
    
    // 执行封装
    OQS_STATUS rc = ctx->kem->encaps(ct, ss, ctx->public_key);
    if (rc != OQS_SUCCESS) {
        return 0;
    }
    
    // 设置输出长度
    if (ctlen) *ctlen = ctx->kem->length_ciphertext;
    if (sslen) *sslen = ctx->kem->length_shared_secret;
    
    printf("KEM 封装成功: %zu 字节密文, %zu 字节共享密钥\n",
           ctx->kem->length_ciphertext, ctx->kem->length_shared_secret);
    
    return 1;
}

// 解封装
int oqs_kem_decapsulate(void *vctx, unsigned char *ss, size_t *sslen,
                       size_t ssmax, const unsigned char *ct, size_t ctlen) {
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx || !ctx->kem || !ctx->secret_key || !ct) {
        return 0;
    }
    
    // 检查输入长度
    if (ctlen != ctx->kem->length_ciphertext) {
        return 0;
    }
    
    // 检查缓冲区大小
    if (ssmax < ctx->kem->length_shared_secret) {
        return 0;
    }
    
    // 执行解封装
    OQS_STATUS rc = ctx->kem->decaps(ss, ct, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        return 0;
    }
    
    // 设置输出长度
    if (sslen) *sslen = ctx->kem->length_shared_secret;
    
    printf("KEM 解封装成功: %zu 字节共享密钥\n", ctx->kem->length_shared_secret);
    
    return 1;
}