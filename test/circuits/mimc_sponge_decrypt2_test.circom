pragma circom 2.0.0;

include "../../circuits/mimcsponge.circom";

template Main() {
	signal input xL_in;
	signal input xR_in;
	signal input k;
	signal output xL_out;
	signal output xR_out;

	component decrypt = MiMCFeistelDecrypt(220);

	decrypt.xL_in <== xL_in;
	decrypt.xR_in <== xR_in;
	decrypt.k <== k;

	decrypt.xL_out ==> xL_out;
	decrypt.xR_out ==> xR_out;
}

component main = Main();
