CFLAGS = -pg -g -Wall -std=c++14 -mpopcnt -march=native

all: test trivial

test: test.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o test test.cpp -lsodium

trivial: trivial.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o trivial test.cpp -lsodium

clean:
	rm -f test
