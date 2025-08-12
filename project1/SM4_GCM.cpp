#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>

// SM4 S盒
static const uint8_t SM4_SBOX[256] = {
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


// SM4固定参数
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

// 循环左移宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM4密钥扩展
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t mk[4], k[36];

    for (int i = 0; i < 4; i++) {
        mk[i] = ((uint32_t)key[i * 4] << 24) |
            ((uint32_t)key[i * 4 + 1] << 16) |
            ((uint32_t)key[i * 4 + 2] << 8) |
            (uint32_t)key[i * 4 + 3];
    }

    for (int i = 0; i < 4; i++) {
        k[i] = mk[i] ^ FK[i];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t temp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];

        uint32_t s = (SM4_SBOX[(temp >> 24) & 0xFF] << 24) |
            (SM4_SBOX[(temp >> 16) & 0xFF] << 16) |
            (SM4_SBOX[(temp >> 8) & 0xFF] << 8) |
            SM4_SBOX[temp & 0xFF];

        uint32_t l = s ^ ROTL32(s, 13) ^ ROTL32(s, 23);

        k[i + 4] = k[i] ^ l;
        rk[i] = k[i + 4];
    }
}

// SM4加密单个块
void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[36];

    for (int i = 0; i < 4; i++) {
        x[i] = ((uint32_t)in[i * 4] << 24) |
            ((uint32_t)in[i * 4 + 1] << 16) |
            ((uint32_t)in[i * 4 + 2] << 8) |
            (uint32_t)in[i * 4 + 3];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t temp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];

        temp = (SM4_SBOX[(temp >> 24) & 0xFF] << 24) |
            (SM4_SBOX[(temp >> 16) & 0xFF] << 16) |
            (SM4_SBOX[(temp >> 8) & 0xFF] << 8) |
            SM4_SBOX[temp & 0xFF];

        temp = temp ^ ROTL32(temp, 2) ^ ROTL32(temp, 10) ^ ROTL32(temp, 18) ^ ROTL32(temp, 24);

        x[i + 4] = x[i] ^ temp;
    }

    for (int i = 0; i < 4; i++) {
        out[i * 4] = (x[35 - i] >> 24) & 0xFF;
        out[i * 4 + 1] = (x[35 - i] >> 16) & 0xFF;
        out[i * 4 + 2] = (x[35 - i] >> 8) & 0xFF;
        out[i * 4 + 3] = x[35 - i] & 0xFF;
    }
}

// 128位异或
static inline void xor_block(uint8_t* dst, const uint8_t* src) {
    for (int i = 0; i < 16; i++) {
        dst[i] ^= src[i];
    }
}

// 增加计数器值
static inline void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

// GCM乘法表结构
typedef struct {
    uint64_t H[16];  // H的16个倍数
    uint8_t H_bytes[16];
} gcm_mult_table;

// 初始化GCM乘法表
void gcm_init_table(const uint8_t H[16], gcm_mult_table* table) {
    // 复制H值
    memcpy(table->H_bytes, H, 16);

    // 初始化表
    uint64_t V[2] = { 0 };
    for (int i = 0; i < 16; i++) {
        table->H[i] = 0;
    }

    // 计算H的16个倍数
    for (int i = 0; i < 128; i++) {
        // 计算当前位对应的表索引
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        int bit = (H[byte_idx] >> bit_idx) & 1;

        if (bit) {
            for (int j = 0; j < 16; j += 8) {
                table->H[j / 8] ^= ((uint64_t)1) << (63 - i);
            }
        }
    }
}

// 使用查表法优化的GCM乘法
void gcm_mult(const gcm_mult_table* table, const uint8_t X[16], uint8_t Y[16]) {
    uint64_t Z[2] = { 0 };

    // 对X的每个字节进行处理
    for (int i = 0; i < 16; i++) {
        uint8_t byte = X[15 - i];  // 从最高字节开始

        // 处理字节的高4位
        uint8_t high = (byte >> 4) & 0x0F;
        if (high != 0) {
            Z[0] ^= table->H[high * 2];
            Z[1] ^= table->H[high * 2 + 1];
        }

        // 处理字节的低4位
        uint8_t low = byte & 0x0F;
        if (low != 0) {
            Z[0] ^= table->H[low * 2];
            Z[1] ^= table->H[low * 2 + 1];
        }
    }

    // 将结果复制回Y
    for (int i = 0; i < 8; i++) {
        Y[7 - i] = (Z[0] >> (i * 8)) & 0xFF;
        Y[15 - i] = (Z[1] >> (i * 8)) & 0xFF;
    }
}
static void zero_block(uint8_t block[16]) {
    memset(block, 0, 16);
}
int sm4_gcm_encrypt(
    const uint8_t* key,        // 16字节密钥
    const uint8_t* iv,         // 初始化向量
    size_t iv_len,             // IV长度
    const uint8_t* aad,        // 附加认证数据
    size_t aad_len,            // AAD长度
    const uint8_t* plaintext,  // 明文
    size_t pt_len,             // 明文长度
    uint8_t* ciphertext,       // 密文输出
    uint8_t* tag               // 认证标签输出 (16字节)
) {
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    // 计算初始计数器值
    uint8_t counter[16] = { 0 };

    uint8_t zero_block_array[16];
    zero_block(zero_block_array);

    if (iv_len == 12) {
        // 标准IV长度
        memcpy(counter, iv, 12);
        counter[15] = 1;
    }
    else {
        uint8_t hash[16] = { 0 };
        gcm_mult_table table;
        uint8_t H[16];

        // 使用zero_block_array
        sm4_encrypt_block(rk, zero_block_array, H);
        gcm_init_table(H, &table);

        // 使用GHASH计算IV哈希
        memset(counter, 0, 16);
        while (iv_len > 0) {
            size_t block_len = (iv_len < 16) ? iv_len : 16;
            uint8_t block[16] = { 0 };
            memcpy(block, iv, block_len);
            xor_block(hash, block);
            gcm_mult(&table, hash, hash);
            iv += block_len;
            iv_len -= block_len;
        }

        // 设置计数器值
        memcpy(counter, hash, 16);
        counter[15] = 1;
    }
    // 计算H = E_K(0)
    uint8_t H[16];
    sm4_encrypt_block(rk, zero_block_array, H);

    // 初始化GHASH表
    gcm_mult_table ghash_table;
    gcm_init_table(H, &ghash_table);

    // 初始化GHASH状态
    uint8_t ghash[16] = { 0 };

    // 处理附加认证数据(AAD)
    size_t aad_blocks = aad_len / 16;
    size_t aad_remainder = aad_len % 16;

    for (size_t i = 0; i < aad_blocks; i++) {
        xor_block(ghash, aad + i * 16);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    if (aad_remainder > 0) {
        uint8_t block[16] = { 0 };
        memcpy(block, aad + aad_blocks * 16, aad_remainder);
        xor_block(ghash, block);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    // 加密数据
    uint8_t current_counter[16];
    uint8_t keystream[16];

    size_t pt_blocks = pt_len / 16;
    size_t pt_remainder = pt_len % 16;

    for (size_t i = 0; i < pt_blocks; i++) {
        // 生成密钥流
        memcpy(current_counter, counter, 16);
        increment_counter(counter);
        sm4_encrypt_block(rk, current_counter, keystream);

        // 加密块
        for (int j = 0; j < 16; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }

        // 更新GHASH
        xor_block(ghash, ciphertext + i * 16);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    // 处理最后一个不完整的块
    if (pt_remainder > 0) {
        memcpy(current_counter, counter, 16);
        increment_counter(counter);
        sm4_encrypt_block(rk, current_counter, keystream);

        for (size_t j = 0; j < pt_remainder; j++) {
            ciphertext[pt_blocks * 16 + j] = plaintext[pt_blocks * 16 + j] ^ keystream[j];
        }

        // 更新GHASH（只处理实际数据部分）
        uint8_t block[16] = { 0 };
        memcpy(block, ciphertext + pt_blocks * 16, pt_remainder);
        xor_block(ghash, block);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    // 处理长度信息 (AAD长度 || 密文长度)
    uint8_t len_block[16] = { 0 };
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)pt_len * 8;

    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
    }

    xor_block(ghash, len_block);
    gcm_mult(&ghash_table, ghash, ghash);

    // 计算最终认证标签
    uint8_t final_counter[16];
    memcpy(final_counter, counter, 16);
    final_counter[15] = 0;  // 用于认证标签的计数器

    uint8_t auth_key[16];
    sm4_encrypt_block(rk, final_counter, auth_key);

    for (int i = 0; i < 16; i++) {
        tag[i] = ghash[i] ^ auth_key[i];
    }

    return 0;
}

// SM4-GCM解密
int sm4_gcm_decrypt(
    const uint8_t* key,         // 16字节密钥
    const uint8_t* iv,          // 初始化向量
    size_t iv_len,              // IV长度
    const uint8_t* aad,         // 附加认证数据
    size_t aad_len,             // AAD长度
    const uint8_t* ciphertext,  // 密文
    size_t ct_len,              // 密文长度
    uint8_t* plaintext,         // 明文输出
    const uint8_t* tag          // 认证标签 (16字节)
) {
    uint32_t rk[32];
    sm4_key_schedule(key, rk);
    uint8_t zero_block_array[16];
    zero_block(zero_block_array);
    // 计算初始计数器值（与加密相同）
    uint8_t counter[16] = { 0 };
    if (iv_len == 12) {
        memcpy(counter, iv, 12);
        counter[15] = 1;
    }
    else {
        uint8_t hash[16] = { 0 };
        gcm_mult_table table;
        uint8_t H[16];
        sm4_encrypt_block(rk,zero_block_array, H);
        gcm_init_table(H, &table);

        memset(counter, 0, 16);
        while (iv_len > 0) {
            size_t block_len = (iv_len < 16) ? iv_len : 16;
            uint8_t block[16] = { 0 };
            memcpy(block, iv, block_len);
            xor_block(hash, block);
            gcm_mult(&table, hash, hash);
            iv += block_len;
            iv_len -= block_len;
        }

        memcpy(counter, hash, 16);
        counter[15] = 1;
    }

    // 计算H = E_K(0)
    uint8_t H[16];
    sm4_encrypt_block(rk, zero_block_array, H);

    // 初始化GHASH表
    gcm_mult_table ghash_table;
    gcm_init_table(H, &ghash_table);

    // 初始化GHASH状态
    uint8_t ghash[16] = { 0 };

    // 处理附加认证数据(AAD)（与加密相同）
    size_t aad_blocks = aad_len / 16;
    size_t aad_remainder = aad_len % 16;

    for (size_t i = 0; i < aad_blocks; i++) {
        xor_block(ghash, aad + i * 16);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    if (aad_remainder > 0) {
        uint8_t block[16] = { 0 };
        memcpy(block, aad + aad_blocks * 16, aad_remainder);
        xor_block(ghash, block);
        gcm_mult(&ghash_table, ghash, ghash);
    }

    // 解密数据
    uint8_t current_counter[16];
    uint8_t keystream[16];

    size_t ct_blocks = ct_len / 16;
    size_t ct_remainder = ct_len % 16;

    // 首先处理完整的块
    for (size_t i = 0; i < ct_blocks; i++) {
        // 更新GHASH（在解密前）
        xor_block(ghash, ciphertext + i * 16);
        gcm_mult(&ghash_table, ghash, ghash);

        // 生成密钥流
        memcpy(current_counter, counter, 16);
        increment_counter(counter);
        sm4_encrypt_block(rk, current_counter, keystream);

        // 解密块
        for (int j = 0; j < 16; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
        }
    }

    // 处理最后一个不完整的块
    if (ct_remainder > 0) {
        // 更新GHASH（在解密前）
        uint8_t block[16] = { 0 };
        memcpy(block, ciphertext + ct_blocks * 16, ct_remainder);
        xor_block(ghash, block);
        gcm_mult(&ghash_table, ghash, ghash);

        // 生成密钥流
        memcpy(current_counter, counter, 16);
        increment_counter(counter);
        sm4_encrypt_block(rk, current_counter, keystream);

        // 解密块
        for (size_t j = 0; j < ct_remainder; j++) {
            plaintext[ct_blocks * 16 + j] = ciphertext[ct_blocks * 16 + j] ^ keystream[j];
        }
    }

    // 处理长度信息 (AAD长度 || 密文长度)
    uint8_t len_block[16] = { 0 };
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;

    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
        len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
    }

    xor_block(ghash, len_block);
    gcm_mult(&ghash_table, ghash, ghash);

    // 计算认证标签
    uint8_t final_counter[16];
    memcpy(final_counter, counter, 16);
    final_counter[15] = 0;  // 用于认证标签的计数器

    uint8_t auth_key[16];
    sm4_encrypt_block(rk, final_counter, auth_key);

    uint8_t computed_tag[16];
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = ghash[i] ^ auth_key[i];
    }

    // 验证标签
    int tag_valid = 1;
    for (int i = 0; i < 16; i++) {
        if (computed_tag[i] != tag[i]) {
            tag_valid = 0;
            break;
        }
    }

    return tag_valid ? 0 : -1;
}

// 测试函数
int main() {
    // 示例数据
    uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b };

    uint8_t aad[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    size_t aad_len = sizeof(aad);

    const char* message = "Hello, this is a test message for SM4-GCM encryption!";
    size_t msg_len = strlen(message);

    // 分配内存
    uint8_t* plaintext = (uint8_t*)malloc(msg_len);
    uint8_t* ciphertext = (uint8_t*)malloc(msg_len);
    uint8_t* decrypted = (uint8_t*)malloc(msg_len);
    uint8_t tag[16];

    memcpy(plaintext, message, msg_len);

    printf("原始明文: %s\n", plaintext);

    // 加密
    sm4_gcm_encrypt(key, iv, 12, aad, aad_len, plaintext, msg_len, ciphertext, tag);
    printf("加密完成，标签: ");
    for (int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n");

    // 解密
    int result = sm4_gcm_decrypt(key, iv, 12, aad, aad_len, ciphertext, msg_len, decrypted, tag);

    if (result == 0) {
        decrypted[msg_len] = '\0';  // 添加字符串终止符
        printf("解密成功: %s\n", decrypted);
    }
    else {
        printf("解密失败: 认证标签不匹配\n");
    }

    // 篡改测试
    printf("\n篡改测试...\n");
    ciphertext[0] ^= 0x01;  // 修改第一个字节

    result = sm4_gcm_decrypt(key, iv, 12, aad, aad_len, ciphertext, msg_len, decrypted, tag);
    if (result == 0) {
        decrypted[msg_len] = '\0';
        printf("解密成功: %s\n", decrypted);
    }
    else {
        printf("解密失败: 认证标签不匹配 (预期结果)\n");
    }

    // 清理
    free(plaintext);
    free(ciphertext);
    free(decrypted);

    return 0;
}
