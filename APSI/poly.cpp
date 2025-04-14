#include "poly.h"

std::vector<int64_t> PolyAdd(
    const std::vector<int64_t>& a,
    const std::vector<int64_t>& b,
    int64_t prime
) {
    std::vector<int64_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = (a[i] + b[i]) % prime;
    }
    return result;
}

std::vector<int64_t> PolySub(
    const std::vector<int64_t>& a,
    const std::vector<int64_t>& b,
    int64_t prime
) {
    std::vector<int64_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = (a[i] - b[i]) % prime;
    }
    return result;
}

std::vector<int64_t> PolyMulTextBook(
    const std::vector<int64_t>& a,
    const std::vector<int64_t>& b,
    int64_t prime
) {
    size_t n = a.size() + b.size() - 1;
    std::vector<int64_t> result(n, 0);
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < b.size(); ++j) {
            result[i + j] += a[i] * b[j];
            result[i + j] %= prime;
        }
    }
    return result;
}


int64_t modInverse(int64_t a, int64_t p) {
    int64_t m0 = p, t, q;
    int64_t x0 = 0, x1 = 1;

    if (p == 1) return 0;

    while (a > 1) {
        // q is quotient
        q = a / p;
        t = p;

        // m is remainder now, process same as Euclid's algorithm
        p = a % p, a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0) x1 += m0;

    return x1;
}

void bit_reverse(std::vector<int64_t>& a) {
    int n = a.size();
    int j = 0;
    for (int i = 1; i < n; ++i) {
        int bit = n >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
}


void PolyNTT(
    std::vector<int64_t>& a, 
    bool invert,
    const std::vector<int64_t>& roots,
    const std::vector<int64_t>& invRoots,
    int64_t prime
) {
    int n = a.size();
    bit_reverse(a);

    for (int len = 2; len <= n; len <<= 1) {
        int level = __builtin_ctz(len);
        int64_t wlen = invert ? invRoots[level] : roots[level];        
        for (int i = 0; i < n; i += len) {
            int64_t w = 1;
            for (int j = 0; j < len / 2; ++j) {
                int64_t u = a[i + j];
                int64_t v = (a[i + j + len / 2] * w) % prime;
                a[i + j] = (u + v) % prime;
                a[i + j + len / 2] = (u - v + prime) % prime;
                w = (w * wlen) % prime;
            }
        }
    }

    if (invert) {
        int64_t n_inv = modInverse(n, prime);
        for (auto& x : a) x = (x * n_inv) % prime;
    }
}

std::vector<int64_t> PolyMultNTT(
    NTTContext &ctx,
    const std::vector<int64_t>& a, 
    const std::vector<int64_t>& b
) {
    uint32_t n = 1;
    while (n < a.size() + b.size() - 1) n <<= 1;

    std::vector<int64_t> fa(a.begin(), a.end()), fb(b.begin(), b.end());
    fa.resize(n);
    fb.resize(n);

    // NTT
    PolyNTT(fa, false, ctx.roots, ctx.invRoots, ctx.prime);
    PolyNTT(fb, false, ctx.roots, ctx.invRoots, ctx.prime);

    // Pointwise multiplication
    for (uint32_t i = 0; i < n; ++i)
        fa[i] = (fa[i] * fb[i]) % ctx.prime;

    // Inverse NTT
    PolyNTT(fa, true, ctx.roots, ctx.invRoots, ctx.prime);

    fa.resize(a.size() + b.size() - 1);  // Trim result
    return fa;
}

std::vector<int64_t> constructInterPolyNaive (
    std::vector<int64_t> vals,
    int64_t prime
) {
    std::vector<int64_t> ret = {(-vals[0])%prime, 1};

    for (uint32_t i = 1; i < vals.size(); i++) {
        ret = PolyMulTextBook(ret, {(-vals[i])%prime, 1}, prime);
    }
    return ret;
}

// Fast Algorithm to compute
// (x-a1)(x-a2)...(x-an)
std::vector<int64_t> constructInterPoly(
    NTTContext ctx,
    std::vector<int64_t> vals
) {
    // x - a
    if (vals.size() == 1) {
        return {(-vals[0])%ctx.prime, 1};
    } else {
        uint32_t n = vals.size();

        // Divide
        std::vector<int64_t> left = constructInterPoly(
            ctx, 
            std::vector<int64_t>(vals.begin(), vals.begin() + n/2)
        );
        std::vector<int64_t> right = constructInterPoly(
            ctx, 
            std::vector<int64_t>(vals.begin() + n/2, vals.end())
        );        

        // Conquer
        if (n > ctx.n / 2) {
            return PolyMulTextBook(left, right, ctx.prime);
        } else {
            return PolyMultNTT(ctx, left, right);
        }

        
    }
}

int64_t PolyEval(
    std::vector<int64_t> coeffs,
    int64_t x,
    int64_t prime
) {
    int64_t ret = 0;
    uint32_t numItems = coeffs.size();
    for (int32_t i = (int)numItems - 1; i >=0 ; i--) {
        ret = (ret * x) % prime;
        ret = (coeffs[i] + ret) % prime;
    }
    return ret;
}