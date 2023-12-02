CC=nvcc
FILES=./src/main.cu ./src/impl.cu ./src/chacha20.cpp

all: ./src/main.cu
	$(CC) -O3 --use_fast_math $(FILES) -o cha