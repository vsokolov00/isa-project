all:
	mkdir build || cd build && cmake .. && make && mv popcl ../popcl
clean:
	rm -rf  ./build popcl