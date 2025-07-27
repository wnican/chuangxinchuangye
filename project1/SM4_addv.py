import struct
from typing import Union, List
import time
# 常量定义
SM4_BLOCK_SIZE = 16  
SM4_KEY_SIZE = 16    
SM4_ROUNDS = 32      

# 预计算S盒和系统参数
SBOX = bytes([
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
])

FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

CK = (
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
)

def _uint32(x: int) -> int:
    #确保返回32位无符号整数
    return x & 0xFFFFFFFF

def _rotate_left(x: int, n: int) -> int:
    #循环左移，优化为32位操作
    return _uint32((x << n) | (x >> (32 - n)))

def _tau(a: int) -> int:
    #优化的非线性变换τ(.)，使用预计算的S盒
    return (SBOX[a >> 24] << 24) | (SBOX[(a >> 16) & 0xFF] << 16) | \
           (SBOX[(a >> 8) & 0xFF] << 8) | SBOX[a & 0xFF]

def _l(b: int) -> int:
    #优化的线性变换L
    return b ^ _rotate_left(b, 2) ^ _rotate_left(b, 10) ^ _rotate_left(b, 18) ^ _rotate_left(b, 24)

def _l_prime(b: int) -> int:
    #优化的线性变换L'
    return b ^ _rotate_left(b, 13) ^ _rotate_left(b, 23)

def _t(x: int) -> int:
    #合成变换T
    return _l(_tau(x))

def _t_prime(x: int) -> int:
    #合成变换T'
    return _l_prime(_tau(x))

def _f(x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
    #优化的轮函数F
    return x0 ^ _t(x1 ^ x2 ^ x3 ^ rk)

class SM4:
    def __init__(self, key: bytes):
        #初始化SM4实例，预计算轮密钥
        if len(key) != SM4_KEY_SIZE:
            raise ValueError(f"Key must be {SM4_KEY_SIZE} bytes long")
        # 将密钥转换为4个32位字
        mk = struct.unpack('>4I', key)        
        # 生成中间密钥K
        k = [_uint32(mk[i] ^ FK[i]) for i in range(4)]       
        # 生成轮密钥rk
        self.rk = []
        for i in range(SM4_ROUNDS):
            temp = k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]
            k.append(_uint32(k[i] ^ _t_prime(temp)))
            self.rk.append(k[i+4])
    
    def _crypt_block(self, block: bytes, decrypt: bool = False) -> bytes:
        #加密/解密单个数据块
        if len(block) != SM4_BLOCK_SIZE:
            raise ValueError(f"Block must be {SM4_BLOCK_SIZE} bytes long")        
        # 将输入数据转换为4个32位字
        x = list(struct.unpack('>4I', block))        
        # 32轮迭代运算
        for i in range(SM4_ROUNDS):
            rk_i = self.rk[SM4_ROUNDS-1-i] if decrypt else self.rk[i]
            x.append(_f(x[i], x[i+1], x[i+2], x[i+3], rk_i))        
        # 反序变换并返回结果
        return struct.pack('>4I', *reversed(x[-4:]))
    
    def encrypt(self, plaintext: Union[bytes, bytearray]) -> bytes:
        #加密数据，自动处理PKCS#7填充
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be bytes or bytearray")        
        padded = self._pad(plaintext)       
        ciphertext = bytearray()
        for i in range(0, len(padded), SM4_BLOCK_SIZE):
            ciphertext.extend(self._crypt_block(padded[i:i+SM4_BLOCK_SIZE]))      
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: Union[bytes, bytearray]) -> bytes:
        #解密数据，自动处理PKCS#7填充
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes or bytearray")
        if len(ciphertext) % SM4_BLOCK_SIZE != 0:
            raise ValueError(f"Ciphertext length must be a multiple of {SM4_BLOCK_SIZE} bytes")  
        # 分块解密
        plaintext = bytearray()
        for i in range(0, len(ciphertext), SM4_BLOCK_SIZE):
            plaintext.extend(self._crypt_block(ciphertext[i:i+SM4_BLOCK_SIZE], decrypt=True))    
        return self._unpad(plaintext)
    
    @staticmethod
    def _pad(data: Union[bytes, bytearray]) -> bytes:
        #PKCS#7填充
        pad_len = SM4_BLOCK_SIZE - (len(data) % SM4_BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)
    
    @staticmethod
    def _unpad(data: Union[bytes, bytearray]) -> bytes:
        #PKCS#7去填充
        if not data:
            return data
        pad_len = data[-1]
        if pad_len > SM4_BLOCK_SIZE or pad_len <= 0:
            raise ValueError("Invalid padding")
        if not all(b == pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid padding")
        return data[:-pad_len]

# 示例
if __name__ == "__main__":
    # 测试密钥和明文
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = b"0123456789abcdeffedcba9876543210"
    
    print(f"Original plaintext ({len(plaintext)} bytes): {plaintext[:50]}...")
    
    # 创建SM4实例
    sm4 = SM4(key)
    
    # 加密
    start = time.time()
    ciphertext = sm4.encrypt(plaintext)
    end = time.time()
    print(f"Ciphertext (hex): {ciphertext.hex()}","加密时间",end-start)
    
    # 解密
    start = time.time()
    decrypted = sm4.decrypt(ciphertext)
    end = time.time()
    print(f"Decrypted plaintext: {decrypted.decode()}","解密时间", end - start)
    
    # 验证
    assert decrypted == plaintext, "Decryption failed!"
    print("Test passed! Plaintext matches after encryption and decryption.")