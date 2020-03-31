cmake_minimum_required(VERSION 3.15)
project(PacketGet)

set(CMAKE_CXX_STANDARD 14)

add_executable(PacketGet main.cpp)
TARGET_LINK_LIBRARIES(PacketGet pcap)