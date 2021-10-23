# =========================================================================================================
#  Case:      Brno University of Technology, ISA - Network Applications and Network Administration
#  Date:      TODO
#  Author:    Vladislav Sokolovskii
#  Contact:   xsokol15@stud.fit.vutbr.cz
#  Description: Makefile which calls the CMake in the correct folder and moves the executable to the root folder
# ========================================================================================================== */

BUILD_DIR := build

CMAKE_COMMAND = cmake -DCMAKE_BUILD_TYPE=Release ..

all:
	mkdir -p ${BUILD_DIR}
	cd ${BUILD_DIR} &&  $(CMAKE_COMMAND)
	cmake --build ${BUILD_DIR}
	mv ${BUILD_DIR}/popcl popcl
clean:
	rm -rf  ./build popcl .oldmails
tar:
	tar -cvf xsokol15.tar CMakeLists.txt src README.md Makefile
