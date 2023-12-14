pragma circom 2.0.0;

include "../../circuits/mimcsponge.circom";

template Main() {
	signal input xL_in;
	signal input xR_in;
	signal input k;
	signal output xL_out;
	signal output xR_out;

	component encrypt = MiMCFeistelEncrypt(220);

	encrypt.xL_in <== xL_in;
	encrypt.xR_in <== xR_in;
	encrypt.k <== k;

	encrypt.xL_out ==> xL_out;
	encrypt.xR_out ==> xR_out;
}

component main = Main();

