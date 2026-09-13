cmake_minimum_required(VERSION 3.4.1)

project(memscanner)

# Define a biblioteca compartilhada
add_library(memscanner SHARED
    memscanner.cpp
)

# Procura bibliotecas do sistema
find_library(log-lib log)
find_library(android-lib android)

# Define flags de compilação e padrão C++17, com DEBUG habilitado para logs
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -O2 -D_GLIBCXX_USE_CXX11_ABI=0 -DDEBUG")

# Linka as bibliotecas
target_link_libraries(memscanner
    ${log-lib}
    ${android-lib}
)