cmake_minimum_required(VERSION 3.22)
project(project C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_COMPILER gcc)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -lcyaml -lyaml")
add_compile_options(-Wall)

add_link_options(-lcyaml)

include(lib/FindPCAP.cmake)

add_executable(project main.c
        src/sniffer.c
        src/interfaces.c
        include/sniffer.h
        include/ethernet.h
        include/config.h
        src/config.c
        include/capture.h
        src/capture.c
)

target_link_libraries(project ${PCAP_LIBRARY})
target_link_libraries(project cyaml)