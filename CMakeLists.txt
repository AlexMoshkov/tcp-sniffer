cmake_minimum_required(VERSION 3.22)
project(tcp-sniffer C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_COMPILER gcc)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -lcyaml -lyaml")
add_compile_options(-Wall)

add_link_options(-lcyaml)

include(lib/FindPCAP.cmake)

add_executable(tcp-sniffer main.c
        src/sniffer.c
        src/interfaces.c
        include/sniffer.h
        include/ethernet.h
        include/config.h
        src/config.c
        include/capture.h
        src/capture.c
        include/ip.h
        include/tcp.h
)

target_link_libraries(tcp-sniffer ${PCAP_LIBRARY})
target_link_libraries(tcp-sniffer cyaml)
