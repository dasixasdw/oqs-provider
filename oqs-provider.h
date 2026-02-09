#ifndef OQS_PROVIDER_H
#define OQS_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>

#ifdef __cplusplus
extern "C" {
#endif

    // 使用 OpenSSL 3.x 中正确的操作 ID
    // 这些值来自 OpenSSL 头文件，但可能因版本而异
#define OSSL_OP_DIGEST        1
#define OSSL_OP_CIPHER        2
#define OSSL_OP_MAC           3
#define OSSL_OP_KDF           4
#define OSSL_OP_RAND          5
#define OSSL_OP_KEYMGMT       10
#define OSSL_OP_KEYEXCH       11
#define OSSL_OP_SIGNATURE     12
#define OSSL_OP_ASYM_CIPHER   13
#define OSSL_OP_KEM           14
#define OSSL_OP_ENCODER       20
#define OSSL_OP_DECODER       21
#define OSSL_OP_STORE         22

    // 导出宏
#if defined(_WIN32)
#ifdef OQS_PROVIDER_EXPORTS
#define OQS_EXPORT __declspec(dllexport)
#else
#define OQS_EXPORT __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define OQS_EXPORT __attribute__((visibility("default")))
#else
#define OQS_EXPORT
#endif

    // Provider 信息
#define OQS_PROVIDER_NAME "oqsprovider"
#define OQS_PROVIDER_VERSION "1.0.0"
#define OQS_PROVIDER_FULLNAME "OQS Provider for Post-Quantum Cryptography"

    // 算法名称标准化
#define OQS_ALG_MLKEM512  "ML-KEM-512"
#define OQS_ALG_MLKEM768  "ML-KEM-768"
#define OQS_ALG_MLKEM1024 "ML-KEM-1024"
#define OQS_ALG_MLDSA44   "ML-DSA-44"
#define OQS_ALG_MLDSA65   "ML-DSA-65"
#define OQS_ALG_MLDSA87   "ML-DSA-87"

    // Provider 初始化函数
    OQS_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                                     const OSSL_DISPATCH *in,
                                     const OSSL_DISPATCH **out,
                                     void **provctx);

#ifdef __cplusplus
}
#endif

#endif // OQS_PROVIDER_H