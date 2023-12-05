# cudacha20
A cuda'ized chacha20. Built as a final project for CS 378 Concurrency Fall 2023.

A detailed construction of this cipher can be found here: https://datatracker.ietf.org/doc/html/rfc8439

## Inspiration
Combining two things I find fun to think about, I thought this would be an interesting build given how 
obviously parallelizable chacha20 is. I also wanted to practice more with general purpose computing using 
GPUs.

## Functionality
Not exactly a stream cipher in a conventional sense since it was built mainly with the purpose of testing 
the speed of this construction and how multithreading could be reasonably handled. Of course, do not use 
this for actually encrypting a file (the key and nonce are hardcoded). It also does not implement the 
Poly1305 authenticator, so it is definitely not safe to use anyway.

## Compile + Usage
Just a simple "make" will automatically get everything set up.

./cha has several arguments:

-i (required): tells the program where the input file is

-o (optional): tells the program where to dump the encrypted file

-t (optional): tells the program to use threads with a specified number of threads

-c (optional, only when -t is specified): tells the program to use this chunk size

-g (optional): tells the program to use GPU with a keystream of specified size
