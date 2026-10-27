// An independent, textbook SHA-256 *compression function* (FIPS 180-4 §6.2.2,
// one block, initial hash value H(0), no padding, no length). Used only to
// cross-check libsnark's gadget: H(a, b) in Zk-Auth is exactly this function
// applied to the 64-byte block a || b.
#pragma once

#include <array>
#include <cstdint>

namespace zk::test {

inline std::array<std::uint8_t, 32> sha256_compress(const std::array<std::uint8_t, 64>& block) {
    static constexpr std::uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    std::uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    auto rotr = [](std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
    std::uint32_t W[64];
    for (int t = 0; t < 16; ++t)
        W[t] = std::uint32_t(block[4 * t]) << 24 | std::uint32_t(block[4 * t + 1]) << 16 |
               std::uint32_t(block[4 * t + 2]) << 8 | std::uint32_t(block[4 * t + 3]);
    for (int t = 16; t < 64; ++t) {
        std::uint32_t s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >> 3);
        std::uint32_t s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >> 10);
        W[t] = W[t - 16] + s0 + W[t - 7] + s1;
    }
    std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (int t = 0; t < 64; ++t) {
        std::uint32_t T1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + W[t];
        std::uint32_t T2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    std::uint32_t out[8] = {H[0] + a, H[1] + b, H[2] + c, H[3] + d, H[4] + e, H[5] + f, H[6] + g, H[7] + h};
    std::array<std::uint8_t, 32> digest;
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) digest[4 * i + j] = std::uint8_t(out[i] >> (24 - 8 * j));
    return digest;
}

} // namespace zk::test
