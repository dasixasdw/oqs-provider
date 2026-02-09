#ifndef OQS_PROVIDER_H
#define OQS_PROVIDER_H

#include <openssl/core.h>
#include <openssl/params.h>

#ifdef __cplusplus
extern "C" {
#endif

    // 导出宏
#if defined(_WIN32) && defined(OQS_PROVIDER_EXPORTS)
#define OQS_EXPORT __declspec(dllexport)
#elif defined(_WIN32) && defined(OQS_PROVIDER_IMPORTS)
#define OQS_EXPORT __declspec(dllimport)
#elif defined(__GNUC__) && defined(OQS_PROVIDER_EXPORTS)
#define OQS_EXPORT __attribute__((visibility("default")))
#else
#define OQS_EXPORT
#endif

    // Provider 信息
#define OQS_PROVIDER_NAME "oqsprovider"
#define OQS_PROVIDER_VERSION "1.0.0"
#define OQS_PROVIDER_FULLNAME "OQS Provider for Post-Quantum Cryptography"

    // 支持的算法
#define OQS_ALG_MLKEM512  "ML-KEM-512"
#define OQS_ALG_MLKEM768  "ML-KEM-768"
#define OQS_ALG_MLKEM1024 "ML-KEM-1024"
#define OQS_ALG_MLDSA44   "ML-DSA-44"
#define OQS_ALG_MLDSA65   "ML-DSA-65"
#define OQS_ALG_MLDSA87   "ML-DSA-87"

    // Provider 初始化函数 (必须导出)
    OQS_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                                     const OSSL_DISPATCH *in,
                                     const OSSL_DISPATCH **out,
                                     void **provctx);

#ifdef __cplusplus
}
#endif

#endif // OQS_PROVIDER_H