CFLAGS = -pg -g -Wall -std=c++14 -mpopcnt -march=native

all: test

test: test.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o test test.cpp -lsodium

clean:
	rm -f test
