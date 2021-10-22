# =========================================================================================================
#  Case:      Brno University of Technology, ISA - Network Applications and Network Administration
#  Date:      TODO
#  Author:    Vladislav Sokolovskii
#  Contact:   xsokol15@stud.fit.vutbr.cz
#  Description: CMake - responsible for the building the project binary file
# ========================================================================================================== */

cmake_minimum_required(VERSION 3.16)

project(popcl)

set(CMAKE_CXX_STANDARD 14)

if(UNIX AND NOT APPLE)
    set(CMAKE_CXX_COMPILER /usr/local/bin/g++)
endif()

if (APPLE)
    set(OPENSSL_INCLUDE_DIR /usr/local/Cellar/openssl@3/3.0.0/include)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")


# If set then program will be outputting some helping/additional information
add_definitions(-DDEBUG)

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
