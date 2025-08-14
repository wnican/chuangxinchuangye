SM2.py文件中实现sm2算法，密钥生成：生成符合SM2标准的公私钥对。加密算法：实现SM2加密流程（C1||C3||C2结构）。解密算法：实现完整的SM2解密流程和验证。辅助函数：模逆运算（扩展欧几里得算法），椭圆曲线点加/点倍运算，标量乘法（双倍-加法算法），密钥派生函数（KDF）。密码学组件：使用HMAC-SHA256作为KDF实现吗，使用SHA-256作为哈希函数
SM2_opt.py对SM2进行了优化，性能上；预计算基点G的倍点表（加速标量乘法），使用NAF（非相邻形式）表示标量减少运算次数，分离基点乘法（使用预计算表）和普通点乘法，优化模运算和点运算算法。安全上使用secrets模块生成密码学安全随机数，添加点验证（防止无效曲线攻击），常数时间比较（防时序攻击），严格检查中间值（如KDF输出全0检测）空间上实现点压缩/解压缩（33字节 vs 64字节），优化内存使用（减少中间变量）
关于签名算法的误用的推导文档
当同一个用户对两个不同消息M1、M2使用相同的k进行签名时：\[r₁ = Hash(ZA||M₁) + x mod n\]

 \[s₁ = (1+dₐ)⁻¹·(k - r₁·dₐ) mod n\] 
  
  \[r₂ = Hash(ZA||M₂) + x mod n\]
  \[s₂ = (1+dₐ)⁻¹·(k - r₂·dₐ) mod n\]

由方程可得：
  \[s₁(1+dₐ) = k - r₁·dₐ\]
  \[s₂(1+dₐ) = k - r₂·dₐ\]

两式相减：
  \[(s₁ - s₂)(1+dₐ) = (r₂ - r₁)dₐ
  => dₐ = (s₂ - s₁) / (s₁ - s₂ + r₁ - r₂) mod n\]
用户 A 和用户 B 使用相同 $k$ 签名不同消息

用户 A 的签名:
$$
\begin{aligned}
kG &= (x, y) \\
r_1 &= \text{Hash}(Z_A \parallel M_1) + x \mod n \\
s_1 &= (1 + d_A)^{-1} \cdot (k - r_1 \cdot d_A) \mod n
\end{aligned}
$$

用户 B 的签名:
$$
\begin{aligned}
kG &= (x, y) \quad \text{(相同 } k \text{)} \\
r_2 &= \text{Hash}(Z_B \parallel M_2) + x \mod n \\
s_2 &= (1 + d_B)^{-1} \cdot (k - r_2 \cdot d_B) \mod n
\end{aligned}
$$

由用户 A 的签名推导 $k$:
$$
k = s_1 (1 + d_A) + r_1 \cdot d_A \mod n
$$

代入用户 B 的签名方程:
$$
s_2 (1 + d_B) = [s_1 (1 + d_A) + r_1 \cdot d_A] - r_2 \cdot d_B
$$

整理得:
$$
d_B = \frac{s_1 (1 + d_A) + r_1 \cdot d_A - s_2}{s_2 + r_2} \mod n
$$


同一私钥 $d$ 在 ECDSA 和 SM2 中使用相同 $k$

ECDSA 签名:
$$
\begin{aligned}
r_1 &= (kG)_x \mod n \\
s_1 &= k^{-1} \cdot (\text{hash}(M_1) + r_1 \cdot d) \mod n
\end{aligned}
$$

SM2 签名:
$$
\begin{aligned}
r_2 &= \text{Hash}(Z_A \parallel M_2) + (kG)_x \mod n \\
s_2 &= (1 + d)^{-1} \cdot (k - r_2 \cdot d) \mod n
\end{aligned}
$$

由 ECDSA 方程推导 $k$:
$$
k = s_1^{-1} \cdot (\text{hash}(M_1) + r_1 \cdot d) \mod n \quad \text{(1)}
$$

由 SM2 方程推导 $k$:
$$
k = s_2 (1 + d) + r_2 \cdot d \mod n \quad \text{(2)}
$$

联立方程 (1) 和 (2):
$$
s_1^{-1} \cdot \text{hash}(M_1) + s_1^{-1} \cdot r_1 \cdot d = s_2 + s_2 \cdot d + r_2 \cdot d
$$

整理得:
$$
d \cdot (s_1^{-1} \cdot r_1 - s_2 - r_2) = s_2 - s_1^{-1} \cdot \text{hash}(M_1)
$$

最终解出 $d$:
$$
d = \frac{s_2 - s_1^{-1} \cdot \text{hash}(M_1)}{s_1^{-1} \cdot r_1 - s_2 - r_2} \mod n
$$
验证在SM2_poc.py中
