CC=nvcc
FILES=main.cu impl.cu chacha20.cpp

all: main.cu
	$(CC) -O3 --use_fast_math $(FILES) -o cha