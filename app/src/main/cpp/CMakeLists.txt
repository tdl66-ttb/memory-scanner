cmake_minimum_required(VERSION 3.10.2)

project(memscanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Biblioteca compartilhada (alvo: Android 11 Go, armv8l = armeabi-v7a, 32 bits)
add_library(memscanner SHARED
    memscanner.cpp
)

find_library(log-lib log)

target_compile_options(memscanner PRIVATE
    -Wall -Wextra
    -fvisibility=hidden        # só os símbolos JNI (JNIEXPORT) ficam visíveis
)

# Logs verbosos (endereços/valores) APENAS em build Debug.
# (removidos: -D_GLIBCXX_USE_CXX11_ABI=0, que não faz nada com libc++, e o -DDEBUG fixo)
target_compile_definitions(memscanner PRIVATE
    $<$<CONFIG:Debug>:MS_DEBUG_LOG>
)

target_link_libraries(memscanner
    ${log-lib}
)
