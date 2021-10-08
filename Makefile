BUILD_DIR := build

all:
	mkdir -p ${BUILD_DIR}
	cd ${BUILD_DIR} && cmake -DOPENSSL_INCLUDE_DIR="/usr/local/Cellar/openssl@3/3.0.0/include" -DCMAKE_BUILD_TYPE=Debug ..
	cmake --build ${BUILD_DIR}
	mv ${BUILD_DIR}/popcl popcl
clean:
	rm -rf  ./build popcl .oldmails
