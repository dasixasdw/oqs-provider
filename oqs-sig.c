#include "oqs-provider.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


// 签名上下文结构
typedef struct {
    OQS_SIG *sig;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
} oqs_sig_ctx;

// 创建签名上下文
void *oqs_sig_newctx(void *provctx, const char *propq) {
    (void)provctx;
    (void)propq;
    
    oqs_sig_ctx *ctx = calloc(1, sizeof(oqs_sig_ctx));
    if (!ctx) {
        return NULL;
    }
    
    return ctx;
}

// 释放签名上下文
void oqs_sig_freectx(void *vctx) {
    oqs_sig_ctx *ctx = (oqs_sig_ctx *)vctx;
    if (!ctx) {
        return;
    }
    
    if (ctx->sig) {
        OQS_SIG_free(ctx->sig);
    }
    
    if (ctx->public_key) {
        free(ctx->public_key);
    }
    
    if (ctx->secret_key) {
        free(ctx->secret_key);
    }
    
    free(ctx);
}

// 初始化签名
int oqs_sig_init(void *vctx, OSSL_PARAM params[]) {
    oqs_sig_ctx *ctx = (oqs_sig_ctx *)vctx;
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
    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        fprintf(stderr, "签名算法 %s 未启用\n", alg_name);
        return 0;
    }
    
    // 创建签名实例
    ctx->sig = OQS_SIG_new(alg_name);
    if (!ctx->sig) {
        fprintf(stderr, "无法创建签名实例: %s\n", alg_name);
        return 0;
    }
    
    return 1;
}

// 生成密钥对
int oqs_sig_keygen(void *vctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb;
    (void)cbarg;
    
    oqs_sig_ctx *ctx = (oqs_sig_ctx *)vctx;
    if (!ctx || !ctx->sig) {
        return 0;
    }
    
    // 分配密钥缓冲区
    ctx->public_key = malloc(ctx->sig->length_public_key);
    ctx->secret_key = malloc(ctx->sig->length_secret_key);
    
    if (!ctx->public_key || !ctx->secret_key) {
        if (ctx->public_key) free(ctx->public_key);
        if (ctx->secret_key) free(ctx->secret_key);
        return 0;
    }
    
    ctx->public_key_len = ctx->sig->length_public_key;
    ctx->secret_key_len = ctx->sig->length_secret_key;
    
    // 生成密钥对
    OQS_STATUS rc = OQS_SIG_keypair(ctx->sig, ctx->public_key, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "签名密钥对生成失败\n");
        return 0;
    }
    
    printf("签名密钥对生成成功: %zu 字节公钥, %zu 字节私钥\n",
           ctx->public_key_len, ctx->secret_key_len);
    
    return 1;
}

// 签名
int oqs_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                size_t sigmax, const unsigned char *tbs, size_t tbslen) {
    oqs_sig_ctx *ctx = (oqs_sig_ctx *)vctx;
    if (!ctx || !ctx->sig || !ctx->secret_key || !tbs) {
        return 0;
    }
    
    // 检查缓冲区大小
    if (sigmax < ctx->sig->length_signature) {
        return 0;
    }
    
    // 执行签名
    size_t actual_sig_len = 0;
    OQS_STATUS rc = OQS_SIG_sign(ctx->sig, sig, &actual_sig_len,
                                tbs, tbslen, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        return 0;
    }
    
    // 设置输出长度
    if (siglen) *siglen = actual_sig_len;
    
    printf("签名成功: %zu 字节消息, %zu 字节签名\n", tbslen, actual_sig_len);
    
    return 1;
}

// 验证
int oqs_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                  const unsigned char *tbs, size_t tbslen) {
    oqs_sig_ctx *ctx = (oqs_sig_ctx *)vctx;
    if (!ctx || !ctx->sig || !ctx->public_key || !sig || !tbs) {
        return 0;
    }
    
    // 执行验证
    OQS_STATUS rc = OQS_SIG_verify(ctx->sig, tbs, tbslen,
                                   sig, siglen, ctx->public_key);
    
    printf("签名验证: %s\n", rc == OQS_SUCCESS ? "成功" : "失败");
    
    return (rc == OQS_SUCCESS) ? 1 : 0;
}