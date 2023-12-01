CC=nvcc
FILES=main.cu impl_single.cpp impl_multi.cpp impl_gpu.cu chacha20.cpp

all: main.cu
	$(CC) -O3 --use_fast_math $(FILES) -o cha