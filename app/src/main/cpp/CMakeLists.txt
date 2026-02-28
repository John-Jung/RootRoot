cmake_minimum_required(VERSION 3.22.1)
project("root_detector")

# 1. Hidden library (obfuscated detection logic)
add_library(
        hidden_detector
        SHARED
        hidden_detector.cpp
)
target_compile_options(hidden_detector PRIVATE -fvisibility=default)

# 2. Main detector library (static/dynamic/dlsym)
add_library(
        native_detector
        SHARED
        native_detector.cpp
)

find_library(log-lib log)

target_link_libraries(
        hidden_detector
        ${log-lib}
)

target_link_libraries(
        native_detector
        ${log-lib}
        dl
)