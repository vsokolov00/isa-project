BUILD_DIR := build

all:
	mkdir -p ${BUILD_DIR}
	cd ${BUILD_DIR} && cmake -DCMAKE_BUILD_TYPE=Release ..
	cmake --build ${BUILD_DIR}
	mv ${BUILD_DIR}/popcl popcl
clean:
	rm -rf  ./build popcl
