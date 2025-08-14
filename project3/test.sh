#!/bin/bash

# 1. 编译电路
echo "编译电路中..."
circom poseidon2.circom --r1cs --wasm --sym -o build

# 2. 可信设置
echo "执行可信设置..."
snarkjs groth16 setup build/poseidon2.r1cs pot16_final.ptau build/poseidon2_0000.zkey
snarkjs zkey contribute build/poseidon2_0000.zkey build/poseidon2_0001.zkey --name="Test Contributor" -v
snarkjs zkey export verificationkey build/poseidon2_0001.zkey build/verification_key.json

# 3. 生成见证
echo "生成见证..."
cd build/poseidon2_js
node generate_witness.js poseidon2.wasm ../../input.json witness.wtns
cd ../..

# 4. 生成证明
echo "生成证明..."
snarkjs groth16 prove build/poseidon2_0001.zkey build/poseidon2_js/witness.wtns build/proof.json build/public.json

# 5. 验证证明
echo "验证证明..."
snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json

# 6. 生成Solidity合约
echo "生成验证合约..."
snarkjs zkey export solidityverifier build/poseidon2_0001.zkey build/Verifier.sol

echo "所有步骤完成！"