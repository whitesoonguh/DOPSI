#ifndef APSI_POLY_H
#define APSI_POLY_H

#include <vector>
#include <cstdint>

int64_t modInverse(int64_t a, int64_t p);


struct NTTContext {
    int64_t prime;
    int64_t root;
    int64_t root_inv;
    int64_t n;
    std::vector<int64_t> roots;
    std::vector<int64_t> invRoots;

    NTTContext(int64_t prime, int64_t root, int64_t n)
        : prime(prime), root(root), n(n) {
        int log_n = __builtin_ctz(n);
        roots.resize(log_n+1);
        invRoots.resize(log_n+1);
        int64_t cur = root; 
        int64_t cur_inv = modInverse(root, prime);
        for (int i = log_n; i >= 1; --i) {
            roots[i] = cur;
            invRoots[i] = cur_inv;
            cur = (cur * cur) % prime;
            cur_inv = (cur_inv * cur_inv) % prime;
        }
    }
};

void PolyNTT(
    std::vector<int64_t>& a, 
    bool invert,
    const std::vector<int64_t>& roots,
    const std::vector<int64_t>& invRoots,
    int64_t prime
);

std::vector<int64_t> PolyMultNTT(
    NTTContext &ctx,
    const std::vector<int64_t>& a, 
    const std::vector<int64_t>& b
);

std::vector<int64_t> PolyMulTextBook(
    const std::vector<int64_t>& a,
    const std::vector<int64_t>& b,
    int64_t prime
);

int64_t PolyEval(
    std::vector<int64_t> coeffs,
    int64_t x,
    int64_t prime
);

std::vector<int64_t> constructInterPolyNaive (
    std::vector<int64_t> vals,
    int64_t prime
);

std::vector<int64_t> constructInterPoly(
    NTTContext ctx,
    std::vector<int64_t> vals
);


#endif