cmake_minimum_required(VERSION 3.22)
project(tcp-sniffer C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_COMPILER gcc)

add_compile_options(-Wall)

include(lib/FindPCAP.cmake)

add_executable(tcp-sniffer
        ${GLIB_INCLUDE_DIRS}
        main.c
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

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB glib-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})
find_path(GLIB_INCLUDE_DIR NAMES glib.h PATH_SUFFIXES glib-2.0)

target_link_libraries(tcp-sniffer ${PCAP_LIBRARY})
target_link_libraries(tcp-sniffer cyaml)
target_link_libraries(tcp-sniffer ${GLIB_LIBRARIES})
