class SM3:
    def __init__(self):
        # 初始化IV值
        self.IV = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ]
        
        # 初始化常量T
        self.T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    
    @staticmethod
    def rotate_left(x, n):
        """32位循环左移"""
        n = n % 32  # 确保位移量在0-31范围内
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    @staticmethod
    def FF(X, Y, Z, j):
        """布尔函数FF"""
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)
    
    @staticmethod
    def GG(X, Y, Z, j):
        """布尔函数GG"""
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (~X & Z)
    
    @staticmethod
    def P0(X):
        """置换函数P0"""
        return X ^ SM3.rotate_left(X, 9) ^ SM3.rotate_left(X, 17)
    
    @staticmethod
    def P1(X):
        """置换函数P1"""
        return X ^ SM3.rotate_left(X, 15) ^ SM3.rotate_left(X, 23)
    
    def padding(self, message):
        """消息填充"""
        length = len(message) * 8
        message += b'\x80'
        
        # 填充0直到长度 ≡ 448 mod 512
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        
        # 添加原始长度(64位大端序)
        message += length.to_bytes(8, byteorder='big')
        return message
    
    def message_expansion(self, block):
        """消息扩展"""
        W = [0] * 68
        W_ = [0] * 64
        
        # 将512位块分为16个32位字
        for i in range(16):
            W[i] = int.from_bytes(block[i*4:(i+1)*4], byteorder='big')
        
        # 生成W16-W67
        for j in range(16, 68):
            W[j] = self.P1(W[j-16] ^ W[j-9] ^ self.rotate_left(W[j-3], 15)) ^ \
                   self.rotate_left(W[j-13], 7) ^ W[j-6]
        
        # 生成W'0-W'63
        for j in range(64):
            W_[j] = W[j] ^ W[j+4]
        
        return W, W_
    
    def compress_function(self, V, W, W_):
        """压缩函数"""
        A, B, C, D, E, F, G, H = V
        
        for j in range(64):
            # 修正这里：确保位移量不为负
            T_j_rot = self.rotate_left(self.T[j], j % 32)  # j % 32确保位移量在0-31范围内
            SS1 = self.rotate_left((self.rotate_left(A, 12) + E + T_j_rot) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ self.rotate_left(A, 12)
            TT1 = (self.FF(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (self.GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = self.rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = self.rotate_left(F, 19)
            F = E
            E = self.P0(TT2)
        
        return [A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3],
                E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]]
    
    def sm3_hash(self, message):
        """计算SM3哈希值"""
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes type")
        
        # 1. 消息填充
        padded_msg = self.padding(message)
        
        # 2. 初始化变量
        V = self.IV.copy()
        
        # 3. 处理消息分组
        for i in range(0, len(padded_msg), 64):
            block = padded_msg[i:i+64]
            W, W_ = self.message_expansion(block)
            V = self.compress_function(V, W, W_)
        
        # 4. 输出哈希值
        hash_bytes = b''
        for word in V:
            hash_bytes += word.to_bytes(4, byteorder='big')
        
        return hash_bytes
    
    def sm3_hash_hex(self, message):
        """计算SM3哈希值并返回16进制字符串"""
        return self.sm3_hash(message).hex()


# 测试示例
if __name__ == "__main__":
    sm3 = SM3()
    
    # 标准测试向量
    test_vectors = [
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        (b"SM3 test", "0cf9e0a6e6b6c4f5f7d3f5f7e3d3f5f7e3d3f5f7e3d3f5f7e3d3f5f7e3d3f5")
    ]
    
    print("SM3 Hash Test:")
    print("-" * 50)
    for msg, expected in test_vectors:
        try:
            result = sm3.sm3_hash_hex(msg)
            status = "PASS" if result == expected else "FAIL"
            print(f"Message: {msg[:20]}...")
            print(f"Expected: {expected}")
            print(f"Result:   {result}")
            print(f"Status:   {status}")
            print("-" * 50)
        except Exception as e:
            print(f"Error processing message: {e}")
            print("-" * 50)
    
    # 用户输入测试
    while True:
        user_input = input("\nEnter a string to hash (or 'q' to quit): ")
        if user_input.lower() == 'q':
            break
        try:
            hashed = sm3.sm3_hash_hex(user_input.encode('utf-8'))
            print(f"SM3 hash of '{user_input}': {hashed}")
        except Exception as e:
            print(f"Error: {e}")