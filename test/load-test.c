// test/load-test.c
#include <stdio.h>
#include <windows.h>

typedef int (*OSSL_PROVIDER_INIT_FUNC)(void *, void *, void **, void **);

int main() {
    HMODULE hModule = LoadLibraryA("oqsprovider.dll");
    if (!hModule) {
        DWORD error = GetLastError();
        printf("❌ 无法加载DLL，错误代码: %lu\n", error);

        // 获取错误消息
        LPVOID lpMsgBuf;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&lpMsgBuf,
            0, NULL);

        printf("错误信息: %s\n", (LPSTR)lpMsgBuf);
        LocalFree(lpMsgBuf);
        return 1;
    }

    printf("✅ DLL加载成功\n");

    // 查找导出函数
    OSSL_PROVIDER_INIT_FUNC init_func =
        (OSSL_PROVIDER_INIT_FUNC)GetProcAddress(hModule, "OSSL_provider_init");

    if (!init_func) {
        printf("❌ 未找到OSSL_provider_init函数\n");

        // 列出所有导出
        printf("\n尝试列出所有导出函数...\n");

        // 使用dumpbin工具
        system("dumpbin /exports oqsprovider.dll");
    } else {
        printf("✅ 找到OSSL_provider_init函数: %p\n", init_func);
    }

    FreeLibrary(hModule);
    return 0;
}