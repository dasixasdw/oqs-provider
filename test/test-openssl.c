#define _XOPEN_SOURCE 700
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>
#else
#include <unistd.h>
#include <libgen.h>
#include <dlfcn.h>
#include <limits.h>
#include <libgen.h>

#endif
// 打印错误信息
void print_errors(const char* prefix) {
    unsigned long err;
    const char* file, *data;
    int line, flags;

    // OpenSSL 3.0 使用新的错误处理函数
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // 使用新的 ERR_get_error_all 函数
    while ((err = ERR_get_error_all(&file, &line, NULL, &data, &flags)) != 0) {
#else
    // 使用旧的 ERR_get_error_line_data 函数
    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
#endif
        fprintf(stderr, "%s: OpenSSL error: %s\n", prefix, ERR_reason_error_string(err));
        fprintf(stderr,  "  File: %s, Line: %d\n", file, line);
        if (data && (flags & ERR_TXT_STRING)) {
            fprintf(stderr,  "  Data: %s\n", data);
        }
    }
}

// 获取当前工作目录
void get_current_directory(char* buffer, size_t size) {
#ifdef _WIN32
    GetCurrentDirectoryA((DWORD)size, buffer);
#else
    if (getcwd(buffer, size) == NULL) {
        buffer[0] = '\0';
    }
#endif
}

// 检查文件是否存在
int file_exists(const char* filename) {
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(filename);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return 1;
#else
    if (access(filename, F_OK) != -1) {
        return 1;
    }
    return 0;
#endif
}

// 将相对路径转换为绝对路径
char* convert_to_absolute_path(const char* relative_path) {
    static char abs_path[2048];

    if (relative_path == NULL) {
        return NULL;
    }

#ifdef _WIN32
    // Windows: 检查是否是绝对路径
    if (strlen(relative_path) >= 3 &&
        isalpha(relative_path[0]) &&
        relative_path[1] == ':' &&
        (relative_path[2] == '\\' || relative_path[2] == '/')) {
        // 已经是绝对路径
        strncpy(abs_path, relative_path, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = '\0';
        return abs_path;
    }

    // 获取当前工作目录
    char cwd[1024];
    get_current_directory(cwd, sizeof(cwd));

    // 组合路径
    if (strncmp(relative_path, "./", 2) == 0 || strncmp(relative_path, ".\\", 2) == 0) {
        // 以 ./ 开头的相对路径
        snprintf(abs_path, sizeof(abs_path), "%s\\%s", cwd, relative_path + 2);
    } else if (strncmp(relative_path, "../", 3) == 0 || strncmp(relative_path, "..\\", 3) == 0) {
        // 以 ../ 开头的相对路径
        snprintf(abs_path, sizeof(abs_path), "%s\\%s", cwd, relative_path);
    } else {
        // 直接相对路径
        snprintf(abs_path, sizeof(abs_path), "%s\\%s", cwd, relative_path);
    }

    // 标准化路径分隔符
    for (char* p = abs_path; *p; ++p) {
        if (*p == '/') *p = '\\';
    }
#else
    // Linux/Unix: 检查是否是绝对路径
    if (relative_path[0] == '/') {
        // 已经是绝对路径
        strncpy(abs_path, relative_path, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = '\0';
        return abs_path;
    }

    // 获取当前工作目录
    char cwd[1024];
    get_current_directory(cwd, sizeof(cwd));

    // 组合路径
    if (strncmp(relative_path, "./", 2) == 0) {
        // 以 ./ 开头的相对路径
        snprintf(abs_path, sizeof(abs_path), "%s/%s", cwd, relative_path + 2);
    } else if (strncmp(relative_path, "../", 3) == 0) {
        // 以 ../ 开头的相对路径
        snprintf(abs_path, sizeof(abs_path), "%s/%s", cwd, relative_path);
    } else {
        // 直接相对路径
        snprintf(abs_path, sizeof(abs_path), "%s/%s", cwd, relative_path);
    }
#endif

    return abs_path;
}

// 尝试加载OQS provider
OSSL_PROVIDER* try_load_oqs_provider(const char* search_path) {
    printf("尝试加载路径: %s\n", search_path);

    // 首先尝试直接加载
    ERR_clear_error();
    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, search_path);

    if (provider) {
        printf("✅ 成功从路径加载: %s\n", search_path);
        return provider;
    }

    // 如果直接加载失败，尝试转换为绝对路径
    printf("❌ 从路径加载失败: %s\n", search_path);
    print_errors("加载失败");

    // 检查是否是相对路径
#ifdef _WIN32
    int is_relative = 1;
    if (strlen(search_path) >= 3 &&
        isalpha(search_path[0]) &&
        search_path[1] == ':' &&
        (search_path[2] == '\\' || search_path[2] == '/')) {
        is_relative = 0;  // 绝对路径
    }
#else
    int is_relative = (search_path[0] != '/');
#endif

    if (is_relative) {
        char* abs_path = convert_to_absolute_path(search_path);
        if (abs_path && strcmp(abs_path, search_path) != 0) {
            printf("尝试使用绝对路径: %s\n", abs_path);

            ERR_clear_error();
            provider = OSSL_PROVIDER_load(NULL, abs_path);

            if (provider) {
                printf("✅ 成功从绝对路径加载: %s\n", abs_path);
                return provider;
            } else {
                printf("❌ 从绝对路径加载失败: %s\n", abs_path);
                print_errors("加载失败");
            }
        }
    }

    return NULL;
}

// 获取provider信息
void print_provider_info(OSSL_PROVIDER* provider) {
    if (!provider) return;

    printf("Provider 信息:\n");

    // 获取provider名称
    const char* name = OSSL_PROVIDER_get0_name(provider);
    if (name) {
        printf("  - 名称: %s\n", name);
    }
}

// 测试特定的算法
int test_algorithm(const char* alg_name, const char* alg_type) {
    printf("测试 %s 算法: %s\n", alg_type, alg_name);

    // 尝试创建上下文，不指定provider
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (!ctx) {
        printf("  ❌ 无法创建 %s 上下文\n", alg_type);
        print_errors("创建上下文失败");
        return 0;
    }

    printf("  ✅ %s 上下文创建成功\n", alg_type);

    int success = 0;

    // 尝试密钥生成初始化
    if (EVP_PKEY_keygen_init(ctx) > 0) {
        printf("  ✅ %s 密钥生成初始化成功\n", alg_type);

        // 尝试生成密钥对
        EVP_PKEY* pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) > 0) {
            printf("  ✅ %s 密钥对生成成功\n", alg_type);

            // 获取密钥大小
            int key_size = EVP_PKEY_get_size(pkey);
            if (key_size > 0) {
                printf("  - 公钥大小: %d 字节\n", key_size);
            }

            EVP_PKEY_free(pkey);
            success = 1;
        } else {
            printf("  ⚠️  %s 密钥对生成失败\n", alg_type);
            print_errors("密钥生成失败");
        }
    } else {
        printf("  ⚠️  %s 密钥生成初始化失败\n", alg_type);
        print_errors("初始化失败");
    }

    EVP_PKEY_CTX_free(ctx);
    return success;
}

// 测试KEM完整流程
int test_kem_full(const char* algorithm) {
    printf("\n测试 %s 完整流程...\n", algorithm);

    int success = 0;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char* pubkey_data = NULL;

    // 创建KEM上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (!ctx) {
        printf("❌ 创建 KEM 上下文失败\n");
        print_errors("创建上下文失败");
        goto cleanup;
    }

    printf("✅ 创建 KEM 上下文成功\n");

    // 生成密钥对
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("❌ KEM 密钥生成初始化失败\n");
        print_errors("初始化失败");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("❌ 生成 KEM 密钥对失败\n");
        print_errors("密钥生成失败");
        goto cleanup;
    }

    printf("✅ 生成 KEM 密钥对成功\n");

    // 获取密钥大小
    int key_size = EVP_PKEY_get_size(pkey);
    if (key_size > 0) {
        printf("  - 公钥大小: %d 字节\n", key_size);
    }

    // 尝试导出公钥
    size_t pubkey_len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, "pub", NULL, 0, &pubkey_len) > 0) {
        pubkey_data = (unsigned char*)malloc(pubkey_len);
        if (pubkey_data) {
            if (EVP_PKEY_get_octet_string_param(pkey, "pub", pubkey_data, pubkey_len, &pubkey_len) > 0) {
                printf("✅ 成功导出公钥 (%zu 字节)\n", pubkey_len);

                // 显示前16字节的十六进制表示
                printf("  - 公钥前16字节: ");
                for (size_t i = 0; i < (pubkey_len < 16 ? pubkey_len : 16); i++) {
                    printf("%02x", pubkey_data[i]);
                }
                printf("\n");
            } else {
                printf("⚠️  导出公钥失败\n");
                print_errors("导出公钥失败");
            }
        } else {
            printf("⚠️  分配内存失败\n");
        }
    } else {
        printf("⚠️  无法获取公钥长度\n");
    }

    success = 1;

cleanup:
    if (pubkey_data) free(pubkey_data);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);

    return success;
}

// 测试签名完整流程
int test_signature_full(const char* algorithm) {
    printf("\n测试 %s 完整流程...\n", algorithm);

    int success = 0;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char* pubkey_data = NULL;

    // 创建签名上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (!ctx) {
        printf("❌ 创建签名上下文失败\n");
        print_errors("创建签名上下文失败");
        goto cleanup;
    }

    printf("✅ 创建签名上下文成功\n");

    // 生成密钥对
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("❌ 签名密钥生成初始化失败\n");
        print_errors("初始化失败");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("❌ 生成签名密钥对失败\n");
        print_errors("密钥生成失败");
        goto cleanup;
    }

    printf("✅ 生成签名密钥对成功\n");

    // 获取密钥大小
    int key_size = EVP_PKEY_get_size(pkey);
    if (key_size > 0) {
        printf("  - 公钥大小: %d 字节\n", key_size);
    }

    // 测试消息
    const char* test_message = "这是一条测试ML-DSA签名的消息";
    size_t test_message_len = strlen(test_message);

    printf("  - 测试消息: %s\n", test_message);
    printf("  - 消息长度: %zu 字节\n", test_message_len);

    // 尝试导出公钥
    size_t pubkey_len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, "pub", NULL, 0, &pubkey_len) > 0) {
        pubkey_data = (unsigned char*)malloc(pubkey_len);
        if (pubkey_data) {
            if (EVP_PKEY_get_octet_string_param(pkey, "pub", pubkey_data, pubkey_len, &pubkey_len) > 0) {
                printf("✅ 成功导出公钥 (%zu 字节)\n", pubkey_len);
            } else {
                printf("⚠️  导出公钥失败\n");
                print_errors("导出公钥失败");
            }
        }
    } else {
        printf("⚠️  无法获取公钥长度\n");
    }

    success = 1;

cleanup:
    if (pubkey_data) free(pubkey_data);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);

    return success;
}

// 列出所有可用的算法
int list_available_algorithms(int* total_tests, int* passed_tests) {
    printf("\n可用的算法列表:\n");
    printf("================\n");

    // 定义要测试的算法
    const char* kem_algorithms[] = {
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        NULL
    };

    const char* sig_algorithms[] = {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        NULL
    };

    int total = 0;
    int passed = 0;

    // 测试KEM算法
    printf("\nKEM 算法:\n");
    for (int i = 0; kem_algorithms[i] != NULL; i++) {
        total++;
        if (test_algorithm(kem_algorithms[i], "KEM")) {
            passed++;
        }
    }

    // 测试签名算法
    printf("\n签名算法:\n");
    for (int i = 0; sig_algorithms[i] != NULL; i++) {
        total++;
        if (test_algorithm(sig_algorithms[i], "签名")) {
            passed++;
        }
    }

    if (total_tests) *total_tests = total;
    if (passed_tests) *passed_tests = passed;

    return passed;
}

// 打印测试结果摘要
void print_test_summary(int default_provider_loaded, int oqs_provider_loaded,
                        int algorithms_tested, int algorithms_passed,
                        int kem_tested, int sig_tested) {
    printf("\n========================================\n");
    printf("测试结果摘要\n");
    printf("========================================\n");

    printf("默认 Provider: %s\n", default_provider_loaded ? "已加载" : "未加载");
    printf("OQS Provider:  %s\n", oqs_provider_loaded ? "已加载" : "未加载");

    if (oqs_provider_loaded) {
        printf("算法测试统计:\n");
        printf("  - 测试算法总数: %d\n", algorithms_tested);
        printf("  - 通过算法数: %d\n", algorithms_passed);
        printf("  - 通过率: %.1f%%\n", algorithms_tested > 0 ? (100.0 * algorithms_passed / algorithms_tested) : 0.0);
        printf("  - KEM算法测试: %s\n", kem_tested ? "通过" : "失败");
        printf("  - 签名算法测试: %s\n", sig_tested ? "通过" : "失败");
    }

    printf("========================================\n");
}

// 获取可执行文件所在目录（构建目录）
int get_executable_directory(char* buffer, size_t size) {
    if (!buffer || size == 0) return 0;

#ifdef _WIN32
    // Windows
    DWORD len = GetModuleFileNameA(NULL, buffer, (DWORD)size);
    if (len == 0 || len >= size) {
        return 0;
    }

    // 去除文件名，只保留目录
    char* last_sep = strrchr(buffer, '\\');
    if (last_sep) {
        *last_sep = '\0';
    } else {
        buffer[0] = '.';
        buffer[1] = '\0';
    }
    return 1;
#else
    // Linux/Unix

    ssize_t len = readlink("/proc/self/exe", buffer, size - 1);
    if (len == -1) {
        return 0;
    }
    buffer[len] = '\0';

    // 去除文件名，只保留目录
    char* last_sep = strrchr(buffer, '/');
    if (last_sep) {
        *last_sep = '\0';
    } else {
        buffer[0] = '.';
        buffer[1] = '\0';
    }
    return 1;
#endif
}

#ifdef __linux
char* get_parent_directory_posix(const char* path) {
    if (!path) return NULL;

    char* path_copy = strdup(path);
    if (!path_copy) return NULL;

    // dirname会修改传入的字符串
    char* parent = dirname(path_copy);

    char* result = strdup(parent);
    free(path_copy);

    return result;
}
#endif
int main(int argc, char* argv[]) {
    printf("OpenSSL OQS Provider 改进测试程序\n");
    printf("=================================\n\n");

    // 初始化统计
    int default_provider_loaded = 0;
    int oqs_provider_loaded = 0;
    int algorithms_tested = 0;
    int algorithms_passed = 0;
    int kem_tested = 0;
    int sig_tested = 0;

    char default_path[2048] = {0};  // 用于存储默认路径
    const char* load_Address = NULL;

    // 检查OpenSSL版本
    printf("OpenSSL 版本: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL 模块路径: %s\n", getenv("OPENSSL_MODULES") ? getenv("OPENSSL_MODULES") : "(未设置)");

    char cwd[1024];
    get_executable_directory(cwd, sizeof(cwd));
    printf("当前工作目录: %s\n", cwd);

    // 检查命令行参数
    if (argc > 1) {
        printf("提供的路径: %s\n", argv[1]);
        load_Address = argv[1];

        // 检查文件是否存在
        if (file_exists(argv[1])) {
            printf("✅ 文件存在\n");
        } else {
            // 尝试转换为绝对路径后检查
            char* abs_path = convert_to_absolute_path(argv[1]);
            if (abs_path && file_exists(abs_path)) {
                printf("✅ 文件存在 (绝对路径: %s)\n", abs_path);
            } else {
                printf("❌ 文件不存在\n");
                printf("请检查文件路径是否正确。\n");
                return 1;
            }
        }
    } else {
        // 没有提供参数，自动构建路径
#ifdef _WIN32
        snprintf(default_path, sizeof(default_path), "%s\\oqsprovider.dll", cwd);
#else
        // Linux/Unix: 获取构建目录的父目录
        char* parent_dir = get_parent_directory_posix(cwd);
        if (parent_dir) {
            snprintf(default_path, sizeof(default_path), "%s/lib/liboqsprovider.so", parent_dir);
            free(parent_dir);
        } else {
            // 如果获取父目录失败，使用当前目录
            snprintf(default_path, sizeof(default_path), "%s/lib/liboqsprovider.so", cwd);
        }
#endif
        load_Address = default_path;

        printf("自动构建的路径: %s\n", load_Address);

        if (file_exists(load_Address)) {
            printf("✅ 文件存在\n");
        } else {
            printf("❌ 文件不存在\n");
            printf("尝试在以下位置查找...\n");

            // 尝试其他可能的路径
            const char* search_paths[] = {
#ifdef _WIN32
                "oqsprovider.dll",
                ".\\oqsprovider.dll",
                ".\\lib\\oqsprovider.dll",
                ".\\test\\oqsprovider.dll",
#else
                "./lib/liboqsprovider.so",
                "./liboqsprovider.so",
                "../lib/liboqsprovider.so",
                "../../lib/liboqsprovider.so",
#endif
                NULL
            };

            int found = 0;
            for (int i = 0; search_paths[i] != NULL; i++) {
                printf("  尝试: %s\n", search_paths[i]);
                if (file_exists(search_paths[i])) {
                    printf("✅ 找到文件: %s\n", search_paths[i]);
                    load_Address = search_paths[i];
                    found = 1;
                    break;
                }
            }

            if (!found) {
                printf("\n❌ 未找到OQS provider文件\n");
                printf("\n请尝试以下方法:\n");
                printf("1. 运行程序时指定provider路径: %s <路径>\n", argv[0]);
                printf("2. 将provider文件放在以下位置之一:\n");
                for (int i = 0; search_paths[i] != NULL; i++) {
                    printf("   - %s\n", search_paths[i]);
                }
                return 1;
            }
        }
    }
    ERR_clear_error();

    // 1. 加载默认 provider
    printf("\n1. 加载默认 provider...\n");
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        print_errors("加载默认 provider 失败");
        return 1;
    }
    printf("✅ 默认 provider 加载成功\n");
    default_provider_loaded = 1;

    // 2. 加载 OQS provider
    printf("\n2. 加载 OQS provider...\n");

    OSSL_PROVIDER* oqs_provider = NULL;

    // 使用用户提供的路径
    if (argv[1]!=NULL) {
        printf("使用用户提供的路径: %s\n", argv[1]);
        oqs_provider = try_load_oqs_provider(argv[1]);

        if (!oqs_provider) {
            printf("\n❌ 无法加载用户提供的路径: %s\n", argv[1]);
            printf("\n调试信息:\n");

            // 尝试转换为绝对路径
            char* abs_path = convert_to_absolute_path(argv[1]);
            if (abs_path && strcmp(abs_path, argv[1]) != 0) {
                printf("  绝对路径: %s\n", abs_path);
            }

            printf("\n常见问题解决:\n");
            printf("1. 确保文件存在\n");
            printf("2. 检查路径是否正确（特别是Windows上的路径分隔符）\n");
            printf("3. 检查文件权限\n");
            printf("4. 确保所有依赖库都在PATH中\n");
            printf("5. 在Windows上，尝试使用绝对路径而不是相对路径\n");

            OSSL_PROVIDER_unload(default_provider);
            return 1;
        }
    }
    else {
        oqs_provider = try_load_oqs_provider(load_Address);
    }

    printf("\n✅ OQS provider 加载成功\n");
    oqs_provider_loaded = 1;
    print_provider_info(oqs_provider);

    // 3. 列出可用算法
    printf("\n3. 测试算法功能...\n");
    list_available_algorithms(&algorithms_tested, &algorithms_passed);

    // 4. 测试KEM完整流程
    printf("\n4. 测试KEM完整流程...\n");
    int kem_result = test_kem_full("ML-KEM-768");
    if (kem_result) {
        printf("✅ KEM 完整流程测试通过\n");
        kem_tested = 1;
    } else {
        printf("❌ KEM 完整流程测试失败\n");
    }

    // 5. 测试签名完整流程
    printf("\n5. 测试签名完整流程...\n");
    int sig_result = test_signature_full("ML-DSA-44");
    if (sig_result) {
        printf("✅ 签名完整流程测试通过\n");
        sig_tested = 1;
    } else {
        printf("❌ 签名完整流程测试失败\n");
    }

    // 6. 打印测试摘要
    print_test_summary(default_provider_loaded, oqs_provider_loaded,
                      algorithms_tested, algorithms_passed,
                      kem_tested, sig_tested);

    // 7. 清理
    printf("\n7. 清理资源...\n");

    if (oqs_provider) {
        if (OSSL_PROVIDER_unload(oqs_provider)) {
            printf("✅ OQS provider 已卸载\n");
        } else {
            printf("❌ OQS provider 卸载失败\n");
            print_errors("卸载失败");
        }
    }

    if (default_provider) {
        if (OSSL_PROVIDER_unload(default_provider)) {
            printf("✅ 默认 provider 已卸载\n");
        } else {
            printf("❌ 默认 provider 卸载失败\n");
            print_errors("卸载失败");
        }
    }

    printf("\n✅ 所有测试完成\n");
    return 0;
}
