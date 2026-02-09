# Oqs-provider使用说明书
## 项目所需支持
liboqs库,openssl库,项目所用编译器为MinGW
## 项目下载
```bush
git clone https://github.com/dasixasdw/oqs-provider
```
## 项目编译及测试
```bush
cd Your_address\oqs-provider
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019" -A x64 ^
  -DOpenSSL_ROOT_DIR="Your_address\OpenSSL" ^ 
  -DOQS_DIR="Your_address\liboqs"
cmake --build . --config Debug                #Windows
make -j$(nproc)                               #linux
# test
cd test
./test-openssl.exe                            #Windows
./test-openssl                                #linux
```
## 项目接口规范
```C
// provider初始化
OSSL_provider_init( 
const OSSL_CORE_HANDLE *handle, 
const OSSL_DISPATCH *in, 
const OSSL_DISPATCH **out, 
void **provctx 
) 

oqs_teardown(void *provctx)   // Provider卸载

oqs_query(void *provctx, int operation_id, int *no_cache)  // 查询支持的算法
//ml-kem算法接口
// 上下文管理
void *oqs_kem_newctx(void *provctx, const char *propq)
void oqs_kem_freectx(void *vctx)

// 算法初始化
int oqs_kem_init(void *vctx, OSSL_PARAM params[])

// 密钥操作
int oqs_kem_keygen(void *vctx, OSSL_CALLBACK *cb, void *cbarg)

int oqs_kem_encapsulate(void *vctx, unsigned char *ct, size_t *ctlen,
                       size_t ctmax, unsigned char *ss, size_t *sslen,
                       size_t ssmax)
                       
int oqs_kem_decapsulate(void *vctx, unsigned char *ss, size_t *sslen,

//ml-dsa算法接口
// 上下文管理
void *oqs_sig_newctx(void *provctx, const char *propq)
void oqs_sig_freectx(void *vctx)

// 算法初始化
int oqs_sig_init(void *vctx, OSSL_PARAM params[])

// 密钥和签名操作
int oqs_sig_keygen(void *vctx, OSSL_CALLBACK *cb, void *cbarg)
int oqs_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                size_t sigmax, const unsigned char *tbs, size_t tbslen)
int oqs_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                  const unsigned char *tbs, size_t tbslen)

//ml-kem上下文
typedef struct {
    OQS_KEM *kem;             // liboqs KEM实例
    uint8_t *public_key;      // 公钥
    size_t public_key_len;    // 公钥长度
    uint8_t *secret_key;      // 私钥
    size_t secret_key_len;    // 私钥长度
} oqs_kem_ctx;

//ml-dsa上下文
typedef struct {
    OQS_SIG *sig;             // liboqs签名实例
    uint8_t *public_key;      // 公钥
    size_t public_key_len;    // 公钥长度
    uint8_t *secret_key;      // 私钥
    size_t secret_key_len;    // 私钥长度
} oqs_sig_ctx;
```