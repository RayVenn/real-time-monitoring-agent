cmake_minimum_required(VERSION 3.16)
project(monitor-cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Emit compile_commands.json so VS Code IntelliSense resolves all include paths
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# nlohmann/json (header-only, fetched at configure time)
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# libpcap
find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h REQUIRED)

# librdkafka C++ (depends on librdkafka C)
find_library(RDKAFKA_CPP_LIBRARY NAMES rdkafka++ REQUIRED)
find_library(RDKAFKA_C_LIBRARY   NAMES rdkafka   REQUIRED)
find_path(RDKAFKA_INCLUDE_DIR NAMES librdkafka/rdkafkacpp.h REQUIRED)

add_executable(monitor
    src/main.cpp
    src/kafka_producer.cpp
)

target_include_directories(monitor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
    ${RDKAFKA_INCLUDE_DIR}
)

target_link_libraries(monitor PRIVATE
    ${PCAP_LIBRARY}
    ${RDKAFKA_CPP_LIBRARY}
    ${RDKAFKA_C_LIBRARY}
    nlohmann_json::nlohmann_json
)

target_compile_options(monitor PRIVATE -Wall -Wextra -O2)
