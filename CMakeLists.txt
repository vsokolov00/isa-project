cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 14)

project(popcl)

set(sources
    src/ArgumentsParser.cpp
        src/MessagesReceiver.cpp
    src/popcl.cpp)
add_executable(popcl ${sources})
