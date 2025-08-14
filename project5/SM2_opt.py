import secrets
import hashlib
import hmac
from typing import Tuple, Optional, List

# SM2曲线参数 (sm2p256v1)
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

class SM2Optimized:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)
        self._precompute_g()
    
    def _precompute_g(self):
        """预计算基点G的倍点加速标量乘法"""
        self.g_table = [None] * 256
        self.g_table[0] = self.G
        for i in range(1, 256):
            self.g_table[i] = self._point_double(self.g_table[i-1])
    
    def _mod_inverse(self, a: int, mod: int) -> int:
        """优化的模逆元计算 (使用扩展欧几里得算法)"""
        # 特殊情况处理
        if a == 0:
            return 0
        if a == 1:
            return 1
            
        lm, hm = 1, 0
        low, high = a % mod, mod
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            lm, low, hm, high = nm, new, lm, low
        return lm % mod

    def _point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """优化的椭圆曲线点加法 (带边界检查)"""
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        # 检查点是否相同或互为逆元
        if x1 == x2:
            if y1 == y2:
                return self._point_double(P)
            return None  # 无穷远点
        
        # 计算斜率
        slope = (y2 - y1) * self._mod_inverse(x2 - x1, self.p)
        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        
        return (x3, y3)

    def _point_double(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """优化的椭圆曲线点加倍"""
        x1, y1 = P
        
        # 计算斜率 (3x² + a)/(2y)
        slope = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p)
        x3 = (slope * slope - 2 * x1) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        
        return (x3, y3)

    def _scalar_mult(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """使用NAF表示的标量乘法 (减少运算次数)"""
        # 生成非相邻形式(NAF)
        naf = self._to_naf(k)
        result = None
        
        # 从最高位开始处理
        for digit in reversed(naf):
            result = self._point_double(result) if result is not None else None
            if digit == 1:
                result = self._point_add(result, P)
            elif digit == -1:
                result = self._point_add(result, self._point_neg(P))
        
        return result

    def _scalar_mult_base(self, k: int) -> Tuple[int, int]:
        """使用预计算表加速基点乘法"""
        result = None
        for i in range(256):
            if k & (1 << i):
                result = self._point_add(result, self.g_table[i])
        return result

    def _to_naf(self, k: int) -> List[int]:
        """转换为非相邻形式(NAF)"""
        naf = []
        while k > 0:
            if k & 1:
                digit = 2 - (k % 4)
                k -= digit
            else:
                digit = 0
            naf.append(digit)
            k >>= 1
        return naf

    def _point_neg(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """点取反"""
        if P is None:
            return None
        x, y = P
        return (x, self.p - y)

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """生成SM2密钥对 (使用密码学安全随机数)"""
        private_key = secrets.randbelow(self.n - 1) + 1
        public_key = self._scalar_mult_base(private_key)
        return private_key, public_key

    def _kdf(self, Z: bytes, klen: int) -> bytes:
        """密钥派生函数 (基于HMAC-SHA256)"""
        v = 256  # 哈希长度
        ct = 0x00000001
        ha = b''
        rounds = (klen + v - 1) // v
        
        for i in range(rounds):
            cts = ct.to_bytes(4, 'big')
            h = hmac.new(Z, cts, hashlib.sha256)
            ha += h.digest()
            ct += 1
        
        return ha[:klen // 8]

    def encrypt(self, public_key: Tuple[int, int], plaintext: bytes) -> bytes:
        """SM2加密算法 (带点压缩)"""
        # 验证公钥有效性
        self._validate_point(public_key)
        
        while True:
            # 生成随机数
            k = secrets.randbelow(self.n - 1) + 1
            C1 = self._scalar_mult_base(k)
            x1, y1 = C1
            x2, y2 = self._scalar_mult(k, public_key)
            t = self._kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(plaintext) * 8)
            if not all(b == 0 for b in t):
                break
        C2 = bytes(a ^ b for a, b in zip(plaintext, t))
        C3 = hashlib.sha256(x2.to_bytes(32, 'big') + plaintext + y2.to_bytes(32, 'big')).digest()
        compressed_C1 = self._compress_point(C1)
        return compressed_C1 + C3 + C2

    def decrypt(self, private_key: int, ciphertext: bytes) -> bytes:
        """SM2解密算法 (支持点压缩)"""
        # 解析密文 (压缩点33字节 + C3=32字节 + C2)
        compressed_C1 = ciphertext[:33]
        C3 = ciphertext[33:65]
        C2 = ciphertext[65:]
        
        # 解压缩点
        C1 = self._decompress_point(compressed_C1)
        
        # 验证点有效性
        self._validate_point(C1)
        
        # 计算[dB]C1 = (x2, y2)
        x2, y2 = self._scalar_mult(private_key, C1)
        
        # 计算t = KDF(x2||y2, len(C2)*8)
        t = self._kdf(x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big'), len(C2) * 8)
        
        # 检查t是否为全0向量
        if all(b == 0 for b in t):
            raise ValueError("KDF produced all-zero value")
        
        # 计算明文 M' = C2 ⊕ t
        plaintext = bytes(a ^ b for a, b in zip(C2, t))
        
        # 计算u = Hash(x2 || M' || y2)
        u = hashlib.sha256(x2.to_bytes(32, 'big') + plaintext + y2.to_bytes(32, 'big')).digest()
        
        # 验证u == C3
        if not self._constant_time_compare(u, C3):
            raise ValueError("C3 verification failed")
        
        return plaintext

    def _compress_point(self, point: Tuple[int, int]) -> bytes:
        """点压缩 (33字节输出)"""
        x, y = point
        # 判断y的奇偶性 (0x02表示偶数，0x03表示奇数)
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')

    def _decompress_point(self, compressed: bytes) -> Tuple[int, int]:
        """点解压缩"""
        prefix = compressed[0]
        x = int.from_bytes(compressed[1:], 'big')
        
        # 计算y² = x³ + ax + b mod p
        y_sq = (x * x * x + self.a * x + self.b) % self.p
        
        # 模平方根计算 (p ≡ 3 mod 4)
        y = pow(y_sq, (self.p + 1) // 4, self.p)
        
        # 根据前缀选择正确的y值
        if prefix == 0x02:
            return (x, y if y % 2 == 0 else self.p - y)
        elif prefix == 0x03:
            return (x, y if y % 2 == 1 else self.p - y)
        else:
            raise ValueError("Invalid point compression prefix")

    def _validate_point(self, point: Tuple[int, int]):
        """验证点是否在曲线上"""
        if point is None:
            raise ValueError("Point at infinity")
        
        x, y = point
        # 验证曲线方程 y² ≡ x³ + ax + b (mod p)
        left = (y * y) % self.p
        right = (x * x * x + self.a * x + self.b) % self.p
        if left != right:
            raise ValueError("Point not on curve")

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """常数时间比较 (防时序攻击)"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

# 示例用法
if __name__ == "__main__":
    sm2 = SM2Optimized()
    
    # 生成密钥对
    private_key, public_key = sm2.generate_keypair()
    print(f"Private key: {hex(private_key)[:20]}...")
    print(f"Public key: (0x{hex(public_key[0])[:10]}..., 0x{hex(public_key[1])[:10]}...)")
    
    # 加密消息
    message = b"Hello, Optimized SM2!"
    ciphertext = sm2.encrypt(public_key, message)
    print(f"\nCiphertext length: {len(ciphertext)} bytes (with point compression)")
    print(f"Ciphertext start: {ciphertext[:20].hex()}...")
    
    # 解密密文
    decrypted = sm2.decrypt(private_key, ciphertext)
    print(f"\nDecrypted: {decrypted.decode()}")
    
    # 性能测试
    import timeit
    setup = "from __main__ import sm2, public_key, private_key, message"
    
    enc_time = timeit.timeit(
        "sm2.encrypt(public_key, message)", 
        setup=setup, 
        number=100
    )
    dec_time = timeit.timeit(
        "sm2.decrypt(private_key, ciphertext)", 
        setup="from __main__ import sm2, private_key, ciphertext",
        number=100
    )
    
    print(f"\nPerformance (100 operations):")
    print(f"Encryption: {enc_time:.4f} seconds")
    print(f"Decryption: {dec_time:.4f} seconds")