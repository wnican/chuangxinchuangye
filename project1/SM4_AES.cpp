#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

// 检测CPU特性
static int has_aesni = 0;
static int has_avx512 = 0;
static int has_gfni = 0;
static int has_avx2 = 0;

// Windows平台CPUID封装
static void get_cpuid(unsigned int leaf, unsigned int* eax, unsigned int* ebx,
    unsigned int* ecx, unsigned int* edx) {
    int regs[4];
    __cpuid(regs, leaf);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
}

static void get_cpuid_count(unsigned int leaf, unsigned int subleaf,
    unsigned int* eax, unsigned int* ebx,
    unsigned int* ecx, unsigned int* edx) {
    int regs[4];
    __cpuidex(regs, leaf, subleaf);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
}

void init_cpu_features() {
    unsigned int eax, ebx, ecx, edx;
    // 检测AES-NI和AVX2
    get_cpuid(1, &eax, &ebx, &ecx, &edx);
    has_aesni = (ecx & (1 << 25)) ? 1 : 0;
    has_avx2 = (ebx & (1 << 5)) ? 1 : 0;
    // 检测AVX512和GFNI
    get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    has_avx512 = (ebx & (1 << 16)) ? 1 : 0;
    has_gfni = (ecx & (1 << 8)) ? 1 : 0;
    printf("CPU Feature Detection:\n");
    printf("AES-NI: %s\n", has_aesni ? "Supported" : "Not supported");
    printf("AVX2: %s\n", has_avx2 ? "Supported" : "Not supported");
    printf("AVX512: %s\n", has_avx512 ? "Supported" : "Not supported");
    printf("GFNI: %s\n", has_gfni ? "Supported" : "Not supported");
}

// S盒定义
static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 系统参数
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 通用函数
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t tau(uint32_t a) {
    uint32_t b = 0;
    b |= (uint32_t)SBOX[(a >> 24) & 0xFF] << 24;
    b |= (uint32_t)SBOX[(a >> 16) & 0xFF] << 16;
    b |= (uint32_t)SBOX[(a >> 8) & 0xFF] << 8;
    b |= (uint32_t)SBOX[a & 0xFF];
    return b;
}

static uint32_t l(uint32_t b) {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

static uint32_t l_prime(uint32_t b) {
    return b ^ rotl32(b, 13) ^ rotl32(b, 23);
}

static uint32_t t(uint32_t x) {
    return l(tau(x));
}

static uint32_t t_prime(uint32_t x) {
    return l_prime(tau(x));
}

// 密钥扩展 - 通用实现
void sm4_key_schedule(const uint8_t* key, uint32_t* rk) {
    uint32_t mk[4], k[36];

    // 将密钥转换为4个字
    for (int i = 0; i < 4; i++) {
        mk[i] = ((uint32_t)key[i * 4] << 24) |
            ((uint32_t)key[i * 4 + 1] << 16) |
            ((uint32_t)key[i * 4 + 2] << 8) |
            (uint32_t)key[i * 4 + 3];
    }
    // 生成轮密钥
    for (int i = 0; i < 4; i++) {
        k[i] = mk[i] ^ FK[i];
    }
    for (int i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
    }
}

// T-table上下文
typedef struct {
    uint32_t rk[32];
    uint32_t T_table[256];
} SM4_TTable_ctx;

void sm4_ttable_init(SM4_TTable_ctx* ctx, const uint8_t* key) {
    // 预计算T-table
    for (int i = 0; i < 256; i++) {
        uint32_t a = (i << 24) | (i << 16) | (i << 8) | i;
        ctx->T_table[i] = l(tau(a));
    }
    // 密钥扩展
    sm4_key_schedule(key, ctx->rk);
}

static inline uint32_t tt(uint32_t x, const uint32_t* T_table) {
    return (T_table[(x >> 24) & 0xFF] & 0xFF000000) ^
        (T_table[(x >> 16) & 0xFF] & 0x00FF0000) ^
        (T_table[(x >> 8) & 0xFF] & 0x0000FF00) ^
        (T_table[x & 0xFF] & 0x000000FF);
}

void sm4_ttable_encrypt_block(const SM4_TTable_ctx* ctx, const uint8_t* plaintext, uint8_t* ciphertext) {
    uint32_t x[36];
    // 加载明文
    for (int i = 0; i < 4; i++) {
        x[i] = ((uint32_t)plaintext[i * 4] << 24) |
            ((uint32_t)plaintext[i * 4 + 1] << 16) |
            ((uint32_t)plaintext[i * 4 + 2] << 8) |
            (uint32_t)plaintext[i * 4 + 3];
    }
    // 32轮加密
    for (int i = 0; i < 32; i++) {
        x[i + 4] = x[i] ^ tt(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ ctx->rk[i], ctx->T_table);
    }
    // 反序变换
    for (int i = 0; i < 4; i++) {
        ciphertext[i * 4] = (x[35 - i] >> 24) & 0xFF;
        ciphertext[i * 4 + 1] = (x[35 - i] >> 16) & 0xFF;
        ciphertext[i * 4 + 2] = (x[35 - i] >> 8) & 0xFF;
        ciphertext[i * 4 + 3] = x[35 - i] & 0xFF;
    }
}

// AES-NI优化实现
#ifdef __AES__
void sm4_aesni_encrypt_block(const uint32_t rk[32], const uint8_t* plaintext, uint8_t* ciphertext) {
    __m128i x0, x1, x2, x3;
    // 加载明文
    x0 = _mm_loadu_si128((__m128i*)plaintext);
    // 反序排列
    const __m128i shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    x0 = _mm_shuffle_epi8(x0, shuffle_mask);
    // 拆分为4个32位字
    x1 = _mm_shuffle_epi32(x0, _MM_SHUFFLE(0, 3, 2, 1));
    x2 = _mm_shuffle_epi32(x0, _MM_SHUFFLE(1, 0, 3, 2));
    x3 = _mm_shuffle_epi32(x0, _MM_SHUFFLE(2, 1, 0, 3));
    x0 = _mm_shuffle_epi32(x0, _MM_SHUFFLE(3, 2, 1, 0));

    // 32轮加密
    for (int i = 0; i < 32; i++) {
        __m128i t = _mm_xor_si128(x1, x2);
        t = _mm_xor_si128(t, x3);
        t = _mm_xor_si128(t, _mm_set1_epi32(rk[i]));
        // 使用AES-NI实现S盒
        t = _mm_aesenc_si128(t, _mm_setzero_si128());
        t = _mm_aesenc_si128(t, _mm_setzero_si128());
        // 线性变换L
        __m128i t2 = _mm_slli_epi32(t, 2);
        __m128i t10 = _mm_slli_epi32(t, 10);
        __m128i t18 = _mm_slli_epi32(t, 18);
        __m128i t24 = _mm_slli_epi32(t, 24);
        t = _mm_xor_si128(t, t2);
        t = _mm_xor_si128(t, t10);
        t = _mm_xor_si128(t, t18);
        t = _mm_xor_si128(t, t24);
        // 轮函数结果
        __m128i x4 = _mm_xor_si128(x0, t);
        // 更新寄存器
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }
    // 合并结果并反序
    x0 = _mm_shuffle_epi32(x0, _MM_SHUFFLE(0, 3, 2, 1));
    x1 = _mm_shuffle_epi32(x1, _MM_SHUFFLE(1, 0, 3, 2));
    x2 = _mm_shuffle_epi32(x2, _MM_SHUFFLE(2, 1, 0, 3));
    x3 = _mm_shuffle_epi32(x3, _MM_SHUFFLE(3, 2, 1, 0));
    __m128i result = _mm_xor_si128(_mm_xor_si128(x0, x1), _mm_xor_si128(x2, x3));
    result = _mm_shuffle_epi8(result, shuffle_mask);
    _mm_storeu_si128((__m128i*)ciphertext, result);
}
#endif
// AVX512+GFNI优化实现
#ifdef __AVX512F__
#ifdef __GFNI__
void sm4_avx512_gfni_encrypt_blocks(const uint32_t rk[32], const uint8_t* plaintexts, uint8_t* ciphertexts, size_t block_count) {
    // 每次处理8个块 (AVX512 512-bit寄存器可以容纳8个64字节块)
    const size_t blocks_per_iter = 8;
    const size_t iters = block_count / blocks_per_iter;
    // 定义常量
    const __m512i shuffle_mask = _mm512_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
    );
    const __m512i affine_matrix = _mm512_set1_epi64(0x1F3F1F3F1F3F1F3F);
    const __m512i multiply_const = _mm512_set1_epi64(0xA5A5A5A5A5A5A5A5);
    const __m512i affine_const = _mm512_set1_epi8(0x63);
    for (size_t i = 0; i < iters; i++) {
        __m512i x0, x1, x2, x3;
        // 加载8个明文块
        x0 = _mm512_loadu_si512((__m512i*)(plaintexts + i * blocks_per_iter * 16));
        // 反序排列
        x0 = _mm512_shuffle_epi8(x0, shuffle_mask);
        // 拆分为4个32位字
        x1 = _mm512_rol_epi32(x0, 8);
        x2 = _mm512_rol_epi32(x0, 16);
        x3 = _mm512_rol_epi32(x0, 24);
        x0 = _mm512_rol_epi32(x0, 0);

        // 32轮加密
        for (int round = 0; round < 32; round++) {
            __m512i t = _mm512_xor_epi32(x1, x2);
            t = _mm512_xor_epi32(t, x3);
            t = _mm512_xor_epi32(t, _mm512_set1_epi32(rk[round]));
            // 使用GFNI实现S盒
            t = _mm512_gf2p8affine_epi64_epi8(t, affine_matrix, 0);
            t = _mm512_gf2p8mul_epi8(t, multiply_const);
            t = _mm512_xor_si512(t, affine_const);
            // 线性变换L
            __m512i t2 = _mm512_rol_epi32(t, 2);
            __m512i t10 = _mm512_rol_epi32(t, 10);
            __m512i t18 = _mm512_rol_epi32(t, 18);
            __m512i t24 = _mm512_rol_epi32(t, 24);
            t = _mm512_xor_epi32(t, t2);
            t = _mm512_xor_epi32(t, t10);
            t = _mm512_xor_epi32(t, t18);
            t = _mm512_xor_epi32(t, t24);
            __m512i x4 = _mm512_xor_epi32(x0, t);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = x4;
        }
        // 合并结果并反序
        x0 = _mm512_rol_epi32(x0, 8);
        x1 = _mm512_rol_epi32(x1, 16);
        x2 = _mm512_rol_epi32(x2, 24);

        __m512i result = _mm512_xor_epi32(_mm512_xor_epi32(x0, x1), _mm512_xor_epi32(x2, x3));
        result = _mm512_shuffle_epi8(result, shuffle_mask);

        _mm512_storeu_si512((__m512i*)(ciphertexts + i * blocks_per_iter * 16), result);
    }
    // 处理剩余不足8个的块
    size_t remaining = block_count % blocks_per_iter;
    if (remaining > 0) {
        uint8_t temp_plain[8 * 16] = { 0 };
        uint8_t temp_cipher[8 * 16] = { 0 };
        memcpy(temp_plain, plaintexts + iters * blocks_per_iter * 16, remaining * 16);

        // 递归调用处理剩余块
        sm4_avx512_gfni_encrypt_blocks(rk, temp_plain, temp_cipher, blocks_per_iter);
        memcpy(ciphertexts + iters * blocks_per_iter * 16, temp_cipher, remaining * 16);
    }
}
#endif
#endif

// 统一加密接口
void sm4_encrypt_blocks(const uint8_t* key, const uint8_t* plaintexts, uint8_t* ciphertexts, size_t block_count) {
    if (block_count == 0) return;
    uint32_t rk[32];
    sm4_key_schedule(key, rk);
    // 根据CPU特性和块数量选择最优实现
#if defined(__AVX512F__) && defined(__GFNI__)
    if (has_avx512 && has_gfni && block_count >= 4) {
        sm4_avx512_gfni_encrypt_blocks(rk, plaintexts, ciphertexts, block_count);
        return;
    }
#endif

#if defined(__AES__)
    if (has_aesni) {
        for (size_t i = 0; i < block_count; i++) {
            sm4_aesni_encrypt_block(rk, plaintexts + i * 16, ciphertexts + i * 16);
        }
        return;
    }
#endif

    // 回退到纯T-table实现
    SM4_TTable_ctx ctx;
    sm4_ttable_init(&ctx, key);
    for (size_t i = 0; i < block_count; i++) {
        sm4_ttable_encrypt_block(&ctx, plaintexts + i * 16, ciphertexts + i * 16);
    }
}

// 辅助函数：打印16进制数据
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    init_cpu_features();
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t plaintext[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t ciphertext[16] = { 0 };
    // 加密测试
    sm4_encrypt_blocks(key, plaintext, ciphertext, 1);
    printf("\nEncryption Test:\n");
    printf("Plaintext:  ");
    print_hex(plaintext, 16);
    printf("Ciphertext: ");
    print_hex(ciphertext, 16);
    uint8_t expected[16] = { 0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46 };
    if (memcmp(ciphertext, expected, 16) == 0) {
        printf("\nTest PASSED!\n");
    }
    else {
        printf("\nTest FAILED!\n");
    }
    // 多块测试
    uint8_t multi_plain[32] = { 0 };
    uint8_t multi_cipher[32] = { 0 };
    memcpy(multi_plain, plaintext, 16);
    memcpy(multi_plain + 16, plaintext, 16);
    sm4_encrypt_blocks(key, multi_plain, multi_cipher, 2);
    printf("\nMulti-block Test:\n");
    printf("Block 1 Cipher: ");
    print_hex(multi_cipher, 16);
    printf("Block 2 Cipher: ");
    print_hex(multi_cipher + 16, 16);
    system("pause"); 
    return 0;
}