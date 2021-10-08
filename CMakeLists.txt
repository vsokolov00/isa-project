cmake_minimum_required(VERSION 3.16)

project(popcl)

set(CMAKE_CXX_STANDARD 14)

#add_definitions(-DDEBUG)

set(sources
    src/popcl.cpp
    src/ArgumentsParser.cpp
    src/MessagesReceiver.cpp)

set(headers
    src/ArgumentsParser.hpp
    src/MessagesReceiver.hpp)

add_executable(${PROJECT_NAME} ${sources} ${headers} ${headers})

find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto)

