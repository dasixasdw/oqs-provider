#include "oqs-provider.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// KEM上下文结构
typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
    int operation; // 0=未设置, 1=封装, 2=解封装
    int initialized;
} oqs_kem_ctx;

// 创建KEM上下文
static void *oqs_kem_newctx(void *provctx)
{
    (void)provctx;

    printf("Debug: %s\n", __func__);

    oqs_kem_ctx *ctx = calloc(1, sizeof(oqs_kem_ctx));
    if (!ctx) {
        return NULL;
    }

    ctx->initialized = 0;
    ctx->operation = 0;
    return ctx;
}

// 释放KEM上下文
static void oqs_kem_freectx(void *vctx)
{
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return;
    }

    printf("Debug: %s\n", __func__);

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

// 复制KEM上下文
static void *oqs_kem_dupctx(void *vctx)
{
    oqs_kem_ctx *src_ctx = (oqs_kem_ctx *)vctx;
    if (!src_ctx) {
        return NULL;
    }

    printf("Debug: %s\n", __func__);

    oqs_kem_ctx *dst_ctx = calloc(1, sizeof(oqs_kem_ctx));
    if (!dst_ctx) {
        return NULL;
    }

    // 浅拷贝基本字段
    dst_ctx->initialized = src_ctx->initialized;
    dst_ctx->operation = src_ctx->operation;

    return dst_ctx;
}

// 封装初始化
static int oqs_kem_encapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{
    (void)provkey;

    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return 0;
    }

    printf("Debug: %s\n", __func__);

    // 查找算法名称
    const char *alg_name = NULL;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "algorithm");
    if (!p) {
        p = OSSL_PARAM_locate_const(params, "group");
    }

    if (p && p->data_type == OSSL_PARAM_UTF8_STRING) {
        alg_name = (const char *)p->data;
    }

    if (!alg_name) {
        fprintf(stderr, "KEM算法名称未指定\n");
        return 0;
    }

    // 检查算法是否启用
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        fprintf(stderr, "KEM算法 %s 未启用\n", alg_name);
        return 0;
    }

    // 创建KEM实例
    ctx->kem = OQS_KEM_new(alg_name);
    if (!ctx->kem) {
        fprintf(stderr, "无法创建KEM实例: %s\n", alg_name);
        return 0;
    }

    // 分配密钥缓冲区并生成密钥对
    ctx->public_key = malloc(ctx->kem->length_public_key);
    ctx->secret_key = malloc(ctx->kem->length_secret_key);

    if (!ctx->public_key || !ctx->secret_key) {
        if (ctx->public_key) free(ctx->public_key);
        if (ctx->secret_key) free(ctx->secret_key);
        ctx->public_key = NULL;
        ctx->secret_key = NULL;
        OQS_KEM_free(ctx->kem);
        ctx->kem = NULL;
        return 0;
    }

    ctx->public_key_len = ctx->kem->length_public_key;
    ctx->secret_key_len = ctx->kem->length_secret_key;

    // 生成密钥对
    OQS_STATUS rc = OQS_KEM_keypair(ctx->kem, ctx->public_key, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "KEM密钥对生成失败\n");
        OQS_KEM_free(ctx->kem);
        free(ctx->public_key);
        free(ctx->secret_key);
        ctx->kem = NULL;
        ctx->public_key = NULL;
        ctx->secret_key = NULL;
        return 0;
    }

    ctx->operation = 1; // 封装操作
    ctx->initialized = 1;

    printf("KEM封装初始化成功: %s\n", alg_name);
    return 1;
}

// 解封装初始化
static int oqs_kem_decapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{
    (void)provkey;

    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return 0;
    }

    printf("Debug: %s\n", __func__);

    // 查找算法名称
    const char *alg_name = NULL;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "algorithm");
    if (!p) {
        p = OSSL_PARAM_locate_const(params, "group");
    }

    if (p && p->data_type == OSSL_PARAM_UTF8_STRING) {
        alg_name = (const char *)p->data;
    }

    if (!alg_name) {
        fprintf(stderr, "KEM算法名称未指定\n");
        return 0;
    }

    // 检查算法是否启用
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        fprintf(stderr, "KEM算法 %s 未启用\n", alg_name);
        return 0;
    }

    // 创建KEM实例
    ctx->kem = OQS_KEM_new(alg_name);
    if (!ctx->kem) {
        fprintf(stderr, "无法创建KEM实例: %s\n", alg_name);
        return 0;
    }

    // 分配密钥缓冲区
    ctx->public_key = malloc(ctx->kem->length_public_key);
    ctx->secret_key = malloc(ctx->kem->length_secret_key);

    if (!ctx->public_key || !ctx->secret_key) {
        if (ctx->public_key) free(ctx->public_key);
        if (ctx->secret_key) free(ctx->secret_key);
        ctx->public_key = NULL;
        ctx->secret_key = NULL;
        OQS_KEM_free(ctx->kem);
        ctx->kem = NULL;
        return 0;
    }

    ctx->public_key_len = ctx->kem->length_public_key;
    ctx->secret_key_len = ctx->kem->length_secret_key;

    // 生成密钥对
    OQS_STATUS rc = OQS_KEM_keypair(ctx->kem, ctx->public_key, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "KEM密钥对生成失败\n");
        OQS_KEM_free(ctx->kem);
        free(ctx->public_key);
        free(ctx->secret_key);
        ctx->kem = NULL;
        ctx->public_key = NULL;
        ctx->secret_key = NULL;
        return 0;
    }

    ctx->operation = 2; // 解封装操作
    ctx->initialized = 1;

    printf("KEM解封装初始化成功: %s\n", alg_name);
    return 1;
}

// 封装操作
static int oqs_kem_encapsulate(void *vctx,
                              unsigned char *ct, size_t *ctlen, size_t ctmax,
                              unsigned char *ss, size_t *sslen, size_t ssmax)
{
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx || !ctx->kem || !ctx->public_key || ctx->operation != 1) {
        return 0;
    }

    printf("Debug: %s\n", __func__);

    // 检查缓冲区大小
    if (ctmax < ctx->kem->length_ciphertext || ssmax < ctx->kem->length_shared_secret) {
        fprintf(stderr, "输出缓冲区太小\n");
        return 0;
    }

    // 执行封装
    OQS_STATUS rc = OQS_KEM_encaps(ctx->kem, ct, ss, ctx->public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "KEM封装失败\n");
        return 0;
    }

    // 设置输出长度
    if (ctlen) *ctlen = ctx->kem->length_ciphertext;
    if (sslen) *sslen = ctx->kem->length_shared_secret;

    printf("KEM封装成功: %zu字节密文, %zu字节共享密钥\n",
           ctx->kem->length_ciphertext, ctx->kem->length_shared_secret);

    return 1;
}

// 解封装操作
static int oqs_kem_decapsulate(void *vctx,
                              unsigned char *ss, size_t *sslen, size_t ssmax,
                              const unsigned char *ct, size_t ctlen)
{
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx || !ctx->kem || !ctx->secret_key || !ct || ctx->operation != 2) {
        return 0;
    }

    printf("Debug: %s\n", __func__);

    // 检查输入长度
    if (ctlen != ctx->kem->length_ciphertext) {
        fprintf(stderr, "密文长度不正确\n");
        return 0;
    }

    // 检查缓冲区大小
    if (ssmax < ctx->kem->length_shared_secret) {
        fprintf(stderr, "共享密钥缓冲区太小\n");
        return 0;
    }

    // 执行解封装
    OQS_STATUS rc = OQS_KEM_decaps(ctx->kem, ss, ct, ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "KEM解封装失败\n");
        return 0;
    }

    // 设置输出长度
    if (sslen) *sslen = ctx->kem->length_shared_secret;

    printf("KEM解封装成功: %zu字节共享密钥\n", ctx->kem->length_shared_secret);

    return 1;
}

// 获取上下文参数
static int oqs_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    oqs_kem_ctx *ctx = (oqs_kem_ctx *)vctx;
    if (!ctx) {
        return 0;
    }

    OSSL_PARAM *p = OSSL_PARAM_locate(params, "operation");
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, ctx->operation)) {
            return 0;
        }
    }

    return 1;
}

// 获取可设置的上下文参数
static const OSSL_PARAM *oqs_kem_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;

    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string("algorithm", NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

// 获取可获取的上下文参数
static const OSSL_PARAM *oqs_kem_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;

    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int("operation", NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

// 设置上下文参数
static int oqs_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

// KEM函数分发表
const OSSL_DISPATCH oqs_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))oqs_kem_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))oqs_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))oqs_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))oqs_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))oqs_kem_settable_ctx_params },
    { 0, NULL }
};