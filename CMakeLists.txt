cmake_minimum_required(VERSION 3.22)
project(tcp-sniffer C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_COMPILER gcc)

add_compile_options(-Wall)

include(lib/FindPCAP.cmake)

add_executable(tcp-sniffer main.c
        src/sniffer.c
        src/interfaces.c
        src/sniffer.h
        src/ethernet.h
        src/config.h
        src/config.c
        src/capture.h
        src/capture.c
        src/ip.h
        src/tcp.h
        src/handlers/handlers.h
        src/handlers/save_pcap.h
        src/handlers/save_pcap.c
        src/handlers/handlers.c
)

target_link_libraries(tcp-sniffer ${PCAP_LIBRARY})
target_link_libraries(tcp-sniffer cyaml)
