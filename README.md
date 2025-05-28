### Introduction

- Large-scale Multi-server Membership Test with Non-Zero Preserving Mapping

- IEEE S&P 2026 Anonymous Submission

### How to compile and run the code

You can compile the code by using the following commands below. Optionally, you can pass a flag `-j` followed by the number of threads you want to speed up the make step. For instance, run `make -j16` to speedup with 16 threads.

```
make clean
rm -r build
mkdir build && cd build
cmake -S .. -B .
make 
```

By building the project, you obtain the executable file `main`.

You can pass cmdline arguments during runtime to change presets while running the program. For instance, to run the program with numItem = 20, lenData = 4, numPack = 1, numAgg = 1, alpha = 3, interType = "CPI" and allowIntersection = `true or false`, run:

```
./main -numItem 20 -lenData 4 -numPack 1 -numAgg 1 -alpha 3 -interType CPI -allowIntersection 1
```

In addition, you can run the code for our implementation of PEPSI (USENIX'24). In this paper, we did not use the hashing technique because it degrades the efficiency for the membership test. We also not considered using the permutation-based hashing as well, which saves the size of the set element by a certain bits that depends on the number of bins of the hash table. You can find an executable file `main_pepsi`. To run the program, you can type the following command (parameter setup for handling 128-bit set elements.) Since We only implemented the logics for the server and client without checking the correctness, the result of the protocol will be inaccurate.

```
./main_pepsi -numItem 20 -bitlen 221 -HW 32 -isEncrypted 0
```

We provide several presets of parameters `(bitlen, HW)` as follows. We used the 80-bit preset throughout our paper.

- 128-bit items: (221, 32) / (132, 64)
- 80-bit items: (89, 32)
- 66-bit items (assuming phash is applied): (70, 32)
- 64-bit items: (117, 16) / (68, 32)
- 32-bit items: (64, 8) / (36, 16)

We also implemented APSI (CCS'21) in OpenFHE for the membership test setting in `APSI/`. You can run the code by

```
./main_apsi -numParties 1024  -isEncrypted 1 -numItems 20
```

Note that current code uses the parameter for `1M-1.json` from the official implemention: https://github.com/microsoft/APSI

### Parameters of the main code

There are several parameters of the code, which is described in the `main.cpp` file. All the details of each codes are as follows. Note that the plaintext modulus is fixed to $p = 2^{16} + 1$. In addition, the consumed depth is automatically calculated according to the parameter setup.

- `numItem`: A number of items (in logarithm of base 2) held by a single data owner.
- `lenData`: A parameter to set the length of the data. The total size would be `(32 * lenData)`
- `numPack`: A parameter to control the number of "sequentially" packed ciphertexts. This is for the comparison with  `1` is default implementation of ours. Note that the setting `numPack = 2 * lenData` is equivalent to the `[KLLW16]` paper. (On the Efficiency of FHE-Based Private Queries, TDSC)
- `numAgg`: A parameter to set the number of elements multiplicatively aggregated. This is for the hybrid aggregation but disabled here. Please set it as 1.
- `alpha`: A parameter that is non-quadratic residue over the finite field of plaintext modulus. `3` is the smallest non-quadratic residue for the plaintext modulus $p=2^{16} + 1$.
- `interType`: A parameter for specifying the type to compute the intersection. Currently, there are four types are implemented.
    - `CI`: It runs `CompInter`, which is a basic intersection protocol.
    - `CPI`: It runs `CompProbInter`, which is a code with the probabilistic reduction technique. Note that this code gives a slower result when the size of each item is $<=64$.

### More stuffs

You can test codes by manually changing the functions in the `main.cpp` the list of possible test codes are here.
- `testEncoding`: Test code for the encoding procedure done by the server.
- `testVAFs`: Test code for running the VAF.
- `testBasicOPs`: Test code for measuring the time for computing 
- `testRotAdd`: Test code for rotation-and-add technique for ciphertext extraction.
- `testProbNPC`: Test code for comparing the running time of the exact NPC and probabilistic NPC. It takes a parameter `k`, which means that each input is represented by a element of $k$-dimensional $\mathbb{F}_{p}$-vector.
- `testAgg`: Test code for measuring the aggregation time. We used the BFV compression technique to reduce both the communication and computation costs. It takes a paramteer `numParties`, which means the number of data owners whose result will be aggregated.
- `testAllBackends`: Test code for running all these backends.

We also provided the scripts to get our experimental results. Make sure that these executables are well placed in the same folder as executables.

#### Enjoy!
