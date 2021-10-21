# =========================================================================================================
#  Case:      Brno University of Technology, ISA - Network Applications and Network Administration
#  Date:      TODO
#  Author:    Vladislav Sokolovskii
#  Contact:   xsokol15@stud.fit.vutbr.cz
#  Description: Makefile which calls the CMake in the correct folder and moves the executable to the root folder
# ========================================================================================================== */

BUILD_DIR := build

CMAKE_COMMAND := cmake 

UNAME_S := $(shell uname -s)

#ifeq ($(UNAME_S),Linux)
#	CMAKE_COMMAND += -DCMAKE_BUILD_TYPE=Debug ..
#else ifeq ($(UNAME_S),Darwin)
#	CMAKE_COMMAND += -DOPENSSL_INCLUDE_DIR="/usr/local/Cellar/openssl@3/3.0.0/include" -DCMAKE_BUILD_TYPE=Debug ..
#endif

CMAKE_COMMAND += -DCMAKE_BUILD_TYPE=Debug ..

all:
	mkdir -p ${BUILD_DIR}
	cd ${BUILD_DIR} &&  $(CMAKE_COMMAND)
	cmake --build ${BUILD_DIR}
	mv ${BUILD_DIR}/popcl popcl
clean:
	rm -rf  ./build popcl .oldmails
