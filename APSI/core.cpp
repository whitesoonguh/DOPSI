#include "APSI_core.h"

// Read JSON Files


// ModPow = a^n mod p
int64_t modPow(int64_t a, int64_t n, int64_t p) {
    int64_t ret = 1;
    int64_t curr = a;
    while (n > 0) {
        if (n % 2) {
            ret = (ret * curr) % p;
        }
        curr = (curr * curr) % p;
        n>>=1;
    }
    return ret;
}


// Compute All Powers from DAG
void compute_all_powers(
    HE &bfv,
    const PowersDag &dag,
    std::vector<Ciphertext<DCRTPoly>> &powers
) {
  // Change this to parallel_apply later?
    dag.parallel_apply([&](const PowersDag::PowersNode &node) {
        if (!node.is_source()) {
        auto parents = node.parents;
        assert(parents.first);
        assert(parents.second);
        assert(parents.first <= powers.size());
        assert(parents.second <= powers.size());

        if (parents.first == parents.second) {
            powers[node.power - 1] =bfv.square(powers[parents.first - 1]);
        } else {
            powers[node.power - 1] = bfv.mult(
                powers[parents.first - 1], powers[parents.second - 1]
            );
        }

        }
    });
}

// Polynomial Evaluation

Ciphertext<DCRTPoly> PolyEvalLinearPtxt(
    HE &bfv,
    std::vector<Plaintext> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers
) {
    uint32_t deg = powers.size();

    if (coeffs.size() != deg + 1) {
        throw std::runtime_error(
            "Degree Mismatch! " + std::to_string(coeffs.size()) + " vs " + std::to_string(deg + 1)
        );
    }

    for (uint32_t i = 0; i < deg; i++) {        
        powers[i] = bfv.mult(powers[i], coeffs[i+1]);
    }
    Ciphertext<DCRTPoly> ret = bfv.addmany(powers);
    ret = bfv.add(coeffs[0], ret);
    return ret;
}

Ciphertext<DCRTPoly> PolyEvalLinearCtxt(
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers
) {
    uint32_t deg = powers.size();

    if (coeffs.size() != deg + 1) {
        throw std::runtime_error(
            "Degree Mismatch! " + std::to_string(coeffs.size()) + " vs " + std::to_string(deg + 1)
        );
    }

    // #pragma omp parallel for
    for (uint32_t i = 0; i < deg; i++) {        
        powers[i] = bfv.mult(powers[i], coeffs[i+1]);
    }
    Ciphertext<DCRTPoly> ret = bfv.addmany(powers);
    ret = bfv.add(coeffs[0], ret);
    return ret;
}

Ciphertext<DCRTPoly> PolyEvalPS(
    HE &bfv,
    std::vector<Plaintext> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers,
    uint32_t ps_low_degree
) {
    uint32_t degree = coeffs.size() - 1;
    uint32_t ps_high_degree = ps_low_degree + 1;
    uint32_t ps_high_degree_powers = degree / ps_high_degree;

    // Temporary Values
    Ciphertext<DCRTPoly> res, _tmp, _tmpIn;

    // First Loop
    for (uint32_t i = 1; i < ps_high_degree_powers; i++) {
        for (uint32_t j = 1; j < ps_high_degree; j++) {
            if (j == 1) {
                _tmpIn = bfv.mult(
                    powers[j-1], coeffs[i * ps_high_degree + j]
                );
            } else {
                _tmp = bfv.mult(
                    powers[j-1], coeffs[i * ps_high_degree + j]
                );
                _tmpIn = bfv.add(_tmpIn, _tmp);
            }
        }
        if (i == 1) {
            res = bfv.mult(
                _tmpIn, powers[i * ps_high_degree - 1]
            );
        } else {
            _tmpIn = bfv.mult(
                _tmpIn, powers[i * ps_high_degree - 1]
            );
            res = bfv.add(res, _tmpIn);
        }
    }
    
    // Second Loops
    if (degree % ps_high_degree > 0) {
        for (uint32_t j = 1; j <= degree % ps_high_degree; j++) {
            if (j == 1) {
                _tmpIn = bfv.mult(
                    powers[j-1],
                    coeffs[ps_high_degree_powers * ps_high_degree + j]
                );
            } else {
                _tmp = bfv.mult(
                    powers[j-1],
                    coeffs[ps_high_degree_powers * ps_high_degree + j]
                );
                _tmpIn = bfv.add(_tmpIn, _tmp);
            }
        }
        _tmpIn = bfv.mult(
            _tmpIn,
            powers[ps_high_degree * ps_high_degree_powers - 1]
        );
        res = bfv.add(res, _tmpIn);        
    }

    // Third Loop
    for (uint32_t j = 1; j < ps_high_degree; j++) {
        _tmp = bfv.mult(powers[j-1], coeffs[j]);
        res = bfv.add(res, _tmp);
    }

    // Fourth loop
    for (uint32_t i = 1; i < ps_high_degree_powers + 1; i++) {
        _tmp = bfv.mult(
            powers[i * ps_high_degree - 1],
            coeffs[i * ps_high_degree]
        );
        res = bfv.add(res, _tmp);
    }
    res = bfv.add(coeffs[0], res);
    return res;
}


// Make a Random Vector
Plaintext makeRandomMask(
    HE &bfv
) {
    std::vector<int64_t> msgVec(bfv.ringDim);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(1, (bfv.prime - 1));

    for (uint32_t i = 0; i < bfv.ringDim; i++) {
        msgVec[i] = dist(gen);
    }
    return bfv.packing(msgVec);
}