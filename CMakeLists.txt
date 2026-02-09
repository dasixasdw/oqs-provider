cmake_minimum_required(VERSION 3.16)
project(oqs-provider VERSION 1.0.0 LANGUAGES C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 设置构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "系统: ${CMAKE_SYSTEM_NAME}")
message(STATUS "处理器: ${CMAKE_SYSTEM_PROCESSOR}")

# 设置输出目录 - 根据平台设置不同的输出目录
# Windows: test目录放库和测试程序，lib目录放库
# Linux: test目录放测试程序，lib目录放库
if(WIN32)
    # Windows: 库文件到/test目录，以便测试程序直接运行
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)  # 可执行文件和DLL
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)  # 动态库
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)   # 静态库/导入库

    # 为库文件单独设置输出目录到lib
    set(LIBRARY_OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib)
    set(ARCHIVE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib)
else()
    # Linux/Unix: 库文件到/lib，可执行文件到/test
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)  # 可执行文件
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)   # 动态库
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)   # 静态库
endif()

# 查找依赖
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "找到 OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL 包含目录: ${OPENSSL_INCLUDE_DIR}")

find_package(liboqs CONFIG REQUIRED)
message(STATUS "找到 liboqs")

# 包含目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# 编译器选项
if(MSVC)
    add_definitions(-DOQS_PROVIDER_EXPORTS -D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_WINSOCK_DEPRECATED_NO_WARNINGS)
    add_compile_options(/W4 /WX-)

    # MSVC特定的链接器选项
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /DEBUG")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /DEBUG")

elseif(MINGW)
    add_definitions(-DOQS_PROVIDER_EXPORTS -D_WIN32_WINNT=0x0600)
    add_compile_options(-Wall -Wextra -Wpedantic -fvisibility=hidden)
    add_compile_options(-fPIC)

elseif(UNIX AND NOT APPLE)
    add_compile_options(-fPIC -pthread -Wall -Wextra -Wpedantic -fvisibility=hidden)

elseif(APPLE)
    add_compile_options(-fPIC -pthread -Wall -Wextra -Wpedantic -fvisibility=hidden)
endif()

# 设置源文件
set(PROVIDER_SOURCES
        oqs-provider.c
        oqs-kem.c
        oqs-sig.c
)

set(MAIN_SOURCE main.c)

# 创建输出目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/test)

# 构建动态库
add_library(${PROJECT_NAME} SHARED ${PROVIDER_SOURCES})

# 设置目标属性 - 根据平台设置不同的输出目录
if(WIN32)
    # Windows: 库文件同时输出到lib和test目录
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${PROJECT_VERSION}
            SOVERSION 1
            OUTPUT_NAME "oqsprovider"
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"  # DLL输出到test目录
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"   # 导入库(.lib)输出到lib目录
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"   # 静态库输出到lib目录
    )
else()
    # Unix-like系统: 库文件到lib目录
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${PROJECT_VERSION}
            SOVERSION 1
            OUTPUT_NAME "oqsprovider"
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"   # 动态库输出到lib目录
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"   # 静态库输出到lib目录
    )
endif()

# 添加导出宏定义
target_compile_definitions(${PROJECT_NAME} PRIVATE
        OQS_PROVIDER_BUILDING_DLL
        OQS_PROVIDER_EXPORTS
)

# 链接库
target_link_libraries(${PROJECT_NAME} PRIVATE OQS::oqs OpenSSL::Crypto)

# 平台特定的链接库
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
            ws2_32
            advapi32
            crypt32
            user32
            bcrypt
    )
endif()

# 平台特定的输出设置
if(MSVC)
    # Visual Studio: 生成.dll和.lib
    set_target_properties(${PROJECT_NAME} PROPERTIES
            PREFIX ""
            SUFFIX ".dll"
            RUNTIME_OUTPUT_NAME "oqsprovider"
            LIBRARY_OUTPUT_NAME "oqsprovider"
            ARCHIVE_OUTPUT_NAME "oqsprovider"
    )

elseif(MINGW)
    # MinGW: 生成.dll和.dll.a
    set_target_properties(${PROJECT_NAME} PROPERTIES
            PREFIX ""
            SUFFIX ".dll"
            IMPORT_SUFFIX ".dll.a"
    )

elseif(APPLE)
    # macOS: 生成.dylib
    set_target_properties(${PROJECT_NAME} PROPERTIES
            PREFIX "lib"
            SUFFIX ".dylib"
    )
else()
    # Linux/Unix: 生成.so
    set_target_properties(${PROJECT_NAME} PROPERTIES
            PREFIX "lib"
            SUFFIX ".so"
    )
endif()

# Windows特定的DLL处理
if(WIN32)
    # 复制主DLL从test目录到lib目录
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:${PROJECT_NAME}>"
            ${CMAKE_BINARY_DIR}/lib
            COMMENT "复制主DLL到lib目录"
    )

    # 查找并复制OpenSSL DLLs
    if(OpenSSL_ROOT_DIR)
        find_path(OPENSSL_BIN_DIR
                NAMES libcrypto-3-x64.dll libcrypto-3.dll libcrypto.dll
                PATHS ${OpenSSL_ROOT_DIR}/bin ${OPENSSL_ROOT_DIR}/bin
                NO_DEFAULT_PATH
        )

        if(OPENSSL_BIN_DIR)
            message(STATUS "找到OpenSSL bin目录: ${OPENSSL_BIN_DIR}")

            # 复制OpenSSL DLLs到test目录
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/libcrypto*.dll"
                    ${CMAKE_BINARY_DIR}/test
                    COMMENT "复制OpenSSL DLLs到test目录"
            )

            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/libssl*.dll"
                    ${CMAKE_BINARY_DIR}/test
            )

            # 同时复制OpenSSL DLLs到lib目录
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/libcrypto*.dll"
                    ${CMAKE_BINARY_DIR}/lib
            )

            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_BIN_DIR}/libssl*.dll"
                    ${CMAKE_BINARY_DIR}/lib
            )
        endif()
    endif()

    # 复制liboqs DLL
    if(OQS_DIR)
        find_file(LIBOQS_DLL
                NAMES liboqs.dll
                PATHS ${OQS_DIR}/bin ${OQS_DIR}/lib
                NO_DEFAULT_PATH
        )

        if(LIBOQS_DLL)
            message(STATUS "找到liboqs DLL: ${LIBOQS_DLL}")

            # 复制liboqs DLL到test目录
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${LIBOQS_DLL}
                    ${CMAKE_BINARY_DIR}/test
                    COMMENT "复制liboqs DLL到test目录"
            )

            # 同时复制liboqs DLL到lib目录
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${LIBOQS_DLL}
                    ${CMAKE_BINARY_DIR}/lib
            )
        endif()
    endif()
else()
    # Unix-like系统: 设置rpath以确保测试程序能找到lib目录中的库
    if(UNIX AND NOT APPLE)
        set_target_properties(${PROJECT_NAME} PROPERTIES
                INSTALL_RPATH "$ORIGIN/../lib"
                BUILD_WITH_INSTALL_RPATH TRUE
        )
    endif()
endif()

# 构建主测试程序
add_executable(${PROJECT_NAME}-test ${MAIN_SOURCE})

# 设置测试程序输出目录
set_target_properties(${PROJECT_NAME}-test PROPERTIES
        OUTPUT_NAME "oqs-test"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
)

target_link_libraries(${PROJECT_NAME}-test PRIVATE
        OQS::oqs
        OpenSSL::Crypto
        ${PROJECT_NAME}
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}-test PRIVATE
            ws2_32
            advapi32
            crypt32
            user32
    )
endif()

# 构建示例程序
option(BUILD_EXAMPLES "构建示例程序" ON)
if(BUILD_EXAMPLES)
    # KEM 测试
    add_executable(test-kem test/test-kem.c)
    set_target_properties(test-kem PROPERTIES
            OUTPUT_NAME "test-kem"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
    target_link_libraries(test-kem PRIVATE
            OQS::oqs
            OpenSSL::Crypto
            ${PROJECT_NAME}
    )

    # 签名测试
    add_executable(test-sig test/test-sig.c)
    set_target_properties(test-sig PROPERTIES
            OUTPUT_NAME "test-sig"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
    target_link_libraries(test-sig PRIVATE
            OQS::oqs
            OpenSSL::Crypto
            ${PROJECT_NAME}
    )

    # OpenSSL 集成测试
    add_executable(test-openssl test/test-openssl.c)
    set_target_properties(test-openssl PROPERTIES
            OUTPUT_NAME "test-openssl"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
    target_link_libraries(test-openssl PRIVATE
            OpenSSL::Crypto
            ${PROJECT_NAME}
    )

    # DLL 加载测试
    add_executable(load-test test/load-test.c)
    set_target_properties(load-test PROPERTIES
            OUTPUT_NAME "load-test"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )

    # 为Unix-like系统设置rpath
    if(UNIX AND NOT APPLE)
        set_target_properties(test-kem test-sig test-openssl load-test ${PROJECT_NAME}-test PROPERTIES
                INSTALL_RPATH "$ORIGIN/../lib"
                BUILD_WITH_INSTALL_RPATH TRUE
        )
    endif()
endif()

# 验证构建
add_custom_target(verify-build ALL
        COMMAND ${CMAKE_COMMAND} -E echo "验证构建..."
        COMMAND ${CMAKE_COMMAND} -E echo "构建目录: ${CMAKE_BINARY_DIR}"
        COMMAND ${CMAKE_COMMAND} -E echo "库目录: ${CMAKE_BINARY_DIR}/lib"
        COMMAND ${CMAKE_COMMAND} -E echo "测试程序目录: ${CMAKE_BINARY_DIR}/test"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_output
        COMMENT "验证构建输出"
)

# 平台特定的验证
if(WIN32)
    add_custom_command(TARGET verify-build POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "=== Windows构建验证 ==="
            COMMAND ${CMAKE_COMMAND} -E echo "检查DLL文件..."
            COMMAND if exist "${CMAKE_BINARY_DIR}/lib/oqsprovider.dll" (
            ${CMAKE_COMMAND} -E echo "✅ lib/oqsprovider.dll 存在"
    ) ELSE (
            ${CMAKE_COMMAND} -E echo "❌ lib/oqsprovider.dll 不存在"
    )
            COMMAND if exist "${CMAKE_BINARY_DIR}/test/oqsprovider.dll" (
            ${CMAKE_COMMAND} -E echo "✅ test/oqsprovider.dll 存在"
    ) ELSE (
            ${CMAKE_COMMAND} -E echo "❌ test/oqsprovider.dll 不存在"
    )
            COMMAND if exist "${CMAKE_BINARY_DIR}/test/oqs-test.exe" (
            ${CMAKE_COMMAND} -E echo "✅ test/oqs-test.exe 存在"
    ) ELSE (
            ${CMAKE_COMMAND} -E echo "❌ test/oqs-test.exe 不存在"
    )
            COMMAND if exist "${CMAKE_BINARY_DIR}/test/test-openssl.exe" (
            ${CMAKE_COMMAND} -E echo "✅ test/test-openssl.exe 存在"
    ) ELSE (
            ${CMAKE_COMMAND} -E echo "❌ test/test-openssl.exe 不存在"
    )
            COMMENT "验证Windows构建"
    )
else()
    add_custom_command(TARGET verify-build POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "=== Unix构建验证 ==="
            COMMAND ${CMAKE_COMMAND} -E echo "检查库文件..."
            COMMAND test -f "${CMAKE_BINARY_DIR}/lib/liboqsprovider.so" &&
            ${CMAKE_COMMAND} -E echo "✅ lib/liboqsprovider.so 存在" ||
            ${CMAKE_COMMAND} -E echo "❌ lib/liboqsprovider.so 不存在"
            COMMAND test -f "${CMAKE_BINARY_DIR}/test/oqs-test" &&
            ${CMAKE_COMMAND} -E echo "✅ test/oqs-test 存在" ||
            ${CMAKE_COMMAND} -E echo "❌ test/oqs-test 不存在"
            COMMAND test -f "${CMAKE_BINARY_DIR}/test/test-openssl" &&
            ${CMAKE_COMMAND} -E echo "✅ test/test-openssl 存在" ||
            ${CMAKE_COMMAND} -E echo "❌ test/test-openssl 不存在"
            COMMENT "验证Unix构建"
    )
endif()

# 安装配置
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
)

install(TARGETS ${PROJECT_NAME}-test
        RUNTIME DESTINATION bin
)

if(BUILD_EXAMPLES)
    install(TARGETS test-kem test-sig test-openssl load-test
            RUNTIME DESTINATION bin
    )
endif()

install(FILES oqs-provider.h DESTINATION include/oqsprovider)

# 构建后总结
add_custom_target(build-summary ALL
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
        COMMAND ${CMAKE_COMMAND} -E echo "构建完成!"
        COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
        if(WIN32)
        COMMAND ${CMAKE_COMMAND} -E echo "Windows构建输出:"
        COMMAND ${CMAKE_COMMAND} -E echo "  lib目录:"
        COMMAND ${CMAKE_COMMAND} -E echo "    - oqsprovider.dll (主库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - oqsprovider.lib (导入库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - libcrypto*.dll (OpenSSL库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - libssl*.dll (OpenSSL库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - liboqs.dll (OQS库)"
        COMMAND ${CMAKE_COMMAND} -E echo "  test目录:"
        COMMAND ${CMAKE_COMMAND} -E echo "    - oqs-test.exe (主测试程序)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-openssl.exe (OpenSSL集成测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-kem.exe (KEM算法测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-sig.exe (签名算法测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - load-test.exe (动态库加载测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - oqsprovider.dll (主库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - libcrypto*.dll (OpenSSL库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - libssl*.dll (OpenSSL库)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - liboqs.dll (OQS库)"
        else()
        COMMAND ${CMAKE_COMMAND} -E echo "Unix构建输出:"
        COMMAND ${CMAKE_COMMAND} -E echo "  lib目录:"
        COMMAND ${CMAKE_COMMAND} -E echo "    - liboqsprovider.so (主库)"
        COMMAND ${CMAKE_COMMAND} -E echo "  test目录:"
        COMMAND ${CMAKE_COMMAND} -E echo "    - oqs-test (主测试程序)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-openssl (OpenSSL集成测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-kem (KEM算法测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - test-sig (签名算法测试)"
        COMMAND ${CMAKE_COMMAND} -E echo "    - load-test (动态库加载测试)"
        endif()
        COMMAND ${CMAKE_COMMAND} -E echo "构建类型: ${CMAKE_BUILD_TYPE}"
        COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
        DEPENDS verify-build
)

# 显示配置摘要
message(STATUS "")
message(STATUS "==========================================")
message(STATUS "OQS Provider 构建配置")
message(STATUS "==========================================")
message(STATUS "项目名称:         ${PROJECT_NAME}")
message(STATUS "版本:            ${PROJECT_VERSION}")
message(STATUS "构建类型:        ${CMAKE_BUILD_TYPE}")
message(STATUS "源文件目录:      ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "构建目录:        ${CMAKE_BINARY_DIR}")
if(WIN32)
    message(STATUS "库文件输出:      ${CMAKE_BINARY_DIR}/lib 和 ${CMAKE_BINARY_DIR}/test")
    message(STATUS "测试程序输出:    ${CMAKE_BINARY_DIR}/test")
    message(STATUS "注意: Windows系统中库文件(DLL)会复制到两个目录")
else()
    message(STATUS "库文件输出:      ${CMAKE_BINARY_DIR}/lib")
    message(STATUS "测试程序输出:    ${CMAKE_BINARY_DIR}/test")
endif()
message(STATUS "安装前缀:        ${CMAKE_INSTALL_PREFIX}")
message(STATUS "C编译器:         ${CMAKE_C_COMPILER}")
message(STATUS "OpenSSL版本:     ${OPENSSL_VERSION}")
message(STATUS "示例构建:        ${BUILD_EXAMPLES}")
message(STATUS "平台:           ${CMAKE_SYSTEM_NAME}")
if(WIN32)
    message(STATUS "Windows输出配置:")
    message(STATUS "  - 主库DLL: lib目录和test目录")
    message(STATUS "  - 导入库: lib目录")
    message(STATUS "  - 测试程序: test目录")
    message(STATUS "  - 依赖DLL: lib目录和test目录")
elseif(APPLE)
    message(STATUS "macOS输出配置:")
    message(STATUS "  - 主库: lib目录 (liboqsprovider.dylib)")
    message(STATUS "  - 测试程序: test目录")
else()
    message(STATUS "Linux输出配置:")
    message(STATUS "  - 主库: lib目录 (liboqsprovider.so)")
    message(STATUS "  - 测试程序: test目录")
endif()
message(STATUS "==========================================")
message(STATUS "")