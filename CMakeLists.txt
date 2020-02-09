cmake_minimum_required(VERSION 3.15)
project(packetdump C)

set(CMAKE_C_STANDARD 99)

aux_source_directory(. DIR_SRCS)

file(GLOB sources "**.c")
SET(pd_sources ${sources})
add_executable(packetdump ${pd_sources})

set(CMAKE_C_FLAGS "-lpcap")