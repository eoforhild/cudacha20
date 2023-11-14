# cudacha20
A cuda'ized chacha20. Built as a final project for CS 378 Concurrency Fall 2023. Still very W.I.P.

A detailed construction of this cipher can be found here: https://datatracker.ietf.org/doc/html/rfc8439

## Inspiration
Combining two things I find fun to think about, I thought this would be an interesting build given how obviously parallelizable chacha20 is. 
I'm not entirely too sure about the parallelizability of the Poly1305 authenticator though as I have not fully read in detail about it.
