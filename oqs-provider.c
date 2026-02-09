#include "oqs-provider.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// 算法信息结构
typedef struct {
    const char *name;
    int is_kem;  // 1 for KEM, 0 for signature
    int enabled;
} oqs_algorithm;

// 支持的算法列表
static oqs_algorithm supported_algorithms[] = {
    {OQS_ALG_MLKEM512, 1, 0},
    {OQS_ALG_MLKEM768, 1, 0},
    {OQS_ALG_MLKEM1024, 1, 0},
    {OQS_ALG_MLDSA44, 0, 0},
    {OQS_ALG_MLDSA65, 0, 0},
    {OQS_ALG_MLDSA87, 0, 0},
    {NULL, 0, 0}
};

// 检查算法是否启用
static void check_algorithms() {
    for (int i = 0; supported_algorithms[i].name != NULL; i++) {
        if (supported_algorithms[i].is_kem) {
            supported_algorithms[i].enabled =
                OQS_KEM_alg_is_enabled(supported_algorithms[i].name);
        } else {
            supported_algorithms[i].enabled =
                OQS_SIG_alg_is_enabled(supported_algorithms[i].name);
        }

        printf("OQS Provider: Algorithm %s is %s\n",
               supported_algorithms[i].name,
               supported_algorithms[i].enabled ? "enabled" : "disabled");
    }
}

// 查询操作
static const OSSL_ALGORITHM *oqs_query(void *provctx, int operation_id,
                                       int *no_cache) {
    (void)provctx;  // 未使用参数
    *no_cache = 0;

    // 这里我们返回一个简单的算法列表
    // 注意：OpenSSL 3.x 的 API 有变化，我们使用更简单的方法

    static OSSL_ALGORITHM kem_algs[] = {
        {OQS_ALG_MLKEM512, "provider=oqsprovider", NULL},
        {OQS_ALG_MLKEM768, "provider=oqsprovider", NULL},
        {OQS_ALG_MLKEM1024, "provider=oqsprovider", NULL},
        {NULL, NULL, NULL}
    };

    static OSSL_ALGORITHM sig_algs[] = {
        {OQS_ALG_MLDSA44, "provider=oqsprovider", NULL},
        {OQS_ALG_MLDSA65, "provider=oqsprovider", NULL},
        {OQS_ALG_MLDSA87, "provider=oqsprovider", NULL},
        {NULL, NULL, NULL}
    };

    // 检查算法启用状态
    check_algorithms();

    // 根据操作类型返回不同的算法列表
    switch (operation_id) {
        case 1:  // 密钥交换操作
            return kem_algs;
        case 2:  // 签名操作
            return sig_algs;
        default:
            return NULL;
    }
}

// Provider 卸载
static int oqs_teardown(void *provctx) {
    (void)provctx;
    printf("OQS Provider: Shutting down...\n");

    return 1;
}

// Provider 分发表
static const OSSL_DISPATCH oqs_dispatch_table[] = {
    { 1, (void (*)(void))oqs_teardown },        // OSSL_FUNC_PROVIDER_TEARDOWN
    { 10, (void (*)(void))oqs_query },          // OSSL_FUNC_PROVIDER_QUERY_OPERATION
    { 0, NULL }
};

// Provider 初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx) {
    (void)handle;
    (void)in;
    (void)provctx;

    printf("Initializing OQS Provider v%s...\n", OQS_PROVIDER_VERSION);

    // 初始化 liboqs
    OQS_init();

    *out = oqs_dispatch_table;

    printf("OQS Provider initialized successfully\n");
    return 1;
}