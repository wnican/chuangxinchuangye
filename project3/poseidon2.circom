pragma circom 2.0.0;
include "circomlib/poseidon.circom";
template Poseidon2Hash() {
	signal input in;	
	signal output out;
	component poseidon = Poseidon(2, 6, 8, 57);
	poseidon.inputs[0] <== in;
	poseidon.inputs[1] <== 0;
	out <== poseidon.out;
}
template Main() {
	signal private input preimage;
	signal public output hash;
	component hasher = Poseidon2Hash();
	hasher.in <== preimage;
	hash <== hasher.out;
}
component main = Main();