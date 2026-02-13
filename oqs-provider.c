#include "oqs-provider.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cmake-build-debug/vcpkg_installed/x64-windows/include/openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>

// 声明外部函数分发表
extern const OSSL_DISPATCH oqs_kem_functions[];
extern const OSSL_DISPATCH oqs_sig_functions[];

// Provider 上下文
typedef struct {
    OSSL_CORE_HANDLE *handle;
    int initialized;
} oqs_provider_ctx;

// 算法表
static const OSSL_ALGORITHM kem_algs[] = {
    {
        OQS_ALG_MLKEM512,
        "provider=" OQS_PROVIDER_NAME,
        oqs_kem_functions,
        "ML-KEM-512 Post-Quantum Key Encapsulation"
    },
    {
        OQS_ALG_MLKEM768,
        "provider=" OQS_PROVIDER_NAME,
        oqs_kem_functions,
        "ML-KEM-768 Post-Quantum Key Encapsulation"
    },
    {
        OQS_ALG_MLKEM1024,
        "provider=" OQS_PROVIDER_NAME,
        oqs_kem_functions,
        "ML-KEM-1024 Post-Quantum Key Encapsulation"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sig_algs[] = {
    {
        OQS_ALG_MLDSA44,
        "provider=" OQS_PROVIDER_NAME,
        oqs_sig_functions,
        "ML-DSA-44 Post-Quantum Signature"
    },
    {
        OQS_ALG_MLDSA65,
        "provider=" OQS_PROVIDER_NAME,
        oqs_sig_functions,
        "ML-DSA-65 Post-Quantum Signature"
    },
    {
        OQS_ALG_MLDSA87,
        "provider=" OQS_PROVIDER_NAME,
        oqs_sig_functions,
        "ML-DSA-87 Post-Quantum Signature"
    },
    { NULL, NULL, NULL, NULL }
};

// 查询操作 - 修复操作 ID 处理
static const OSSL_ALGORITHM *oqs_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx; // 未使用参数

    // 必须设置no_cache=1，否则算法数组会被丢弃
    *no_cache = 1;

    printf("OQS Provider: Query operation %d\n", operation_id);

    // 处理支持的操作 ID
    switch (operation_id) {
        case OSSL_OP_KEM:
            printf("OQS Provider: Returning KEM algorithms\n");
            return kem_algs;
        case OSSL_OP_SIGNATURE:
            printf("OQS Provider: Returning signature algorithms\n");
            return sig_algs;
        default:
            // 对于不支持的操作，静默返回 NULL
            // OpenSSL 会查询多个操作 ID，这是正常的
            return NULL;
    }
}

// Provider卸载函数
static void oqs_teardown(void *provctx)
{
    oqs_provider_ctx *ctx = (oqs_provider_ctx *)provctx;
    if (ctx) {
        printf("OQS Provider: Shutting down\n");
        free(ctx);
    }
}

// 修复参数查询函数
static const OSSL_PARAM *oqs_gettable_params(void *provctx)
{
    (void)provctx; // 未使用参数

    static const OSSL_PARAM param_table[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };
    return param_table;
}

static int oqs_get_params(void *provctx, OSSL_PARAM params[])
{
    oqs_provider_ctx *ctx = (oqs_provider_ctx *)provctx;
    OSSL_PARAM *p;
    int ret = 1;

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL) {
        if (!OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_NAME)) {
            ret = 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_VERSION)) {
            ret = 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL) {
        if (!OSSL_PARAM_set_utf8_ptr(p, "OQS Provider with liboqs")) {
            ret = 0;
        }
    }

    return ret;
}

// Provider分发表
static const OSSL_DISPATCH oqs_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))oqs_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))oqs_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))oqs_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))oqs_get_params },
    { 0, NULL }
};

// Provider初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    printf("=== OQS PROVIDER INIT (OpenSSL 3.x Compatible) ===\n");

    // 记录传入的调度表
    if (in != NULL) {
        printf("Received %zu dispatch entries\n", (size_t)(in - in));
        // 可以遍历调度表来了解可用的核心函数
        const OSSL_DISPATCH *dispatch = in;
        while (dispatch->function_id != 0) {
            printf("Available core function: %d\n", dispatch->function_id);
            dispatch++;
        }
    }

    // 验证输入参数
    if (handle == NULL || out == NULL || provctx == NULL) {
        printf("❌ Invalid parameters provided to OSSL_provider_init\n");
        return 0;
    }

    // 分配Provider上下文
    oqs_provider_ctx *ctx = calloc(1, sizeof(oqs_provider_ctx));
    if (!ctx) {
        printf("❌ Failed to allocate provider context\n");
        return 0;
    }

    // 初始化上下文
    ctx->handle = (OSSL_CORE_HANDLE *)handle;
    ctx->initialized = 1;

    // 设置输出参数
    *out = oqs_dispatch_table;
    *provctx = ctx;

    // 记录初始化成功信息
    printf("✅ OQS Provider %s initialized successfully\n", OQS_PROVIDER_VERSION);
    printf("Provider name: %s\n", OQS_PROVIDER_NAME);
    printf("Provider handle: %p\n", (void*)handle);

    return 1;
}
//