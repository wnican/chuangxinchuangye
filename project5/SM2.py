import hashlib
import hmac
import os
import random
from typing import Tuple, Optional

# 定义SM2椭圆曲线参数 (sm2p256v1曲线)
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)
    
    def _mod_inverse(self, a: int, mod: int) -> int:
        """计算模逆元 (扩展欧几里得算法)"""
        if a == 0:
            return 0
        lm, hm = 1, 0
        low, high = a % mod, mod
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            lm, low, hm, high = nm, new, lm, low
        return lm % mod

    def _point_add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加法"""
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 != y2:
            return None  # 无穷远点
        
        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p)
        else:
            m = (y2 - y1) * self._mod_inverse(x2 - x1, self.p)
        
        m %= self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        
        return (x3, y3)

    def _point_double(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加倍"""
        return self._point_add(P, P)

    def _scalar_mult(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """标量乘法 (使用双倍-加法算法)"""
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self._point_add(result, addend)
            addend = self._point_double(addend)
            k >>= 1
        
        return result

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对"""
        private_key = random.randint(1, self.n - 1)
        public_key = self._scalar_mult(private_key, self.G)
        return private_key, public_key

    def _kdf(self, Z: bytes, klen: int) -> bytes:
        """密钥派生函数 (KDF)"""
        v = 256  # SM3哈希长度 (256位)
        ct = 0x00000001
        ha = b''
        
        for i in range((klen + v - 1) // v):
            cts = ct.to_bytes(4, 'big')
            h = hmac.new(Z, cts, hashlib.sha256)
            ha += h.digest()
            ct += 1
        
        return ha[:klen // 8]

    def encrypt(self, public_key: Tuple[int, int], plaintext: bytes) -> bytes:
        k = random.randint(1, self.n - 1)
        C1 = self._scalar_mult(k, self.G)
        x1, y1 = C1
        x2, y2 = self._scalar_mult(k, public_key)
        
        t = self._kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(plaintext) * 8)
        if all(b == 0 for b in t):
            return self.encrypt(public_key, plaintext)
        C2 = bytes(a ^ b for a, b in zip(plaintext, t))
        C3 = hashlib.sha256(x2.to_bytes(32, 'big') + plaintext + y2.to_bytes(32, 'big')).digest()
        return x1.to_bytes(32, 'big') + y1.to_bytes(32, 'big') + C3 + C2

    def decrypt(self, private_key: int, ciphertext: bytes) -> bytes:
        """SM2解密算法"""
        # 解析密文 (C1=64字节, C3=32字节, C2=剩余部分)
        x1 = int.from_bytes(ciphertext[:32], 'big')
        y1 = int.from_bytes(ciphertext[32:64], 'big')
        C3 = ciphertext[64:96]
        C2 = ciphertext[96:]
        
        # 验证C1是否在曲线上
        C1 = (x1, y1)
        
        # 步骤2: 计算[dB]C1 = (x2, y2)
        x2, y2 = self._scalar_mult(private_key, C1)
        
        # 步骤3: 计算t = KDF(x2||y2, len(C2)*8)
        t = self._kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(C2) * 8)
        
        # 如果t是全0向量则报错
        if all(b == 0 for b in t):
            raise ValueError("KDF produced all-zero value")
        
        # 步骤4: 计算明文 M' = C2 ⊕ t
        plaintext = bytes(a ^ b for a, b in zip(C2, t))
        
        # 步骤5: 计算u = Hash(x2 || M' || y2)
        u = hashlib.sha256(x2.to_bytes(32, 'big') + plaintext + y2.to_bytes(32, 'big')).digest()
        
        # 步骤6: 验证u == C3
        if u != C3:
            raise ValueError("C3 verification failed")
        
        return plaintext

# 示例用法
if __name__ == "__main__":
    sm2 = SM2()
    
    # 生成密钥对
    private_key, public_key = sm2.generate_keypair()
    print(f"Private key: {hex(private_key)[:20]}...")
    print(f"Public key: (0x{hex(public_key[0])[:10]}..., 0x{hex(public_key[1])[:10]}...)")
    
    # 加密消息
    message = b"Hello, SM2 Encryption!"
    ciphertext = sm2.encrypt(public_key, message)
    print(f"\nCiphertext ({len(ciphertext)} bytes): {ciphertext[:20]}...")
    
    # 解密密文
    decrypted = sm2.decrypt(private_key, ciphertext)
    print(f"\nDecrypted: {decrypted.decode()}")