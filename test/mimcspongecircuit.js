const chai = require("chai");
const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const { keccak256 } = require("@ethersproject/keccak256");

const buildMimcSponge = require("circomlibjs").buildMimcSponge;

const assert = chai.assert;

describe("MiMC Sponge Circuit test", function () {
    let circuit;
    let mimcSponge;
    let F;

    this.timeout(100000);

    before( async () => {
        mimcSponge = await buildMimcSponge();
        F = mimcSponge.F;
    });

    it("Should encrypt and decrypt with same key", async () => {
        const key = BigInt(keccak256("0x03"));

        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_encrypt_test.circom"));

        const xL_in = 42069n;
        const xR_in = 12345n;

        const w = await circuit.calculateWitness({xL_in, xR_in, k: key});
        await circuit.checkConstraints(w);

        if (!circuit.symbols) await circuit.loadSymbols();
        const xL_enc = w[circuit.symbols['main.xL_out'].varIdx];
        const xR_enc = w[circuit.symbols['main.xR_out'].varIdx];


        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_decrypt2_test.circom"));

        const w2 = await circuit.calculateWitness({xL_in: xL_enc, xR_in: xR_enc, k: key});
        await circuit.checkConstraints(w2);

        if (!circuit.symbols) await circuit.loadSymbols();
        const xL_dec = w2[circuit.symbols['main.xL_out'].varIdx];
        const xR_dec = w2[circuit.symbols['main.xR_out'].varIdx];

        assert.strictEqual(xL_dec, xL_in);
        assert.strictEqual(xR_dec, xR_in);
    });

    it("Should encrypt and decrypt a single message", async () => {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_decrypt_test.circom"));

        const w = await circuit.calculateWitness({xL_in: 1, xR_in: 2, k: 3});

        await circuit.assertOut(w, {xL_out: '1', xR_out: '2'});

        await circuit.checkConstraints(w);
    });

    it("Should fail to encrypt and decrypt a single message with different keys", async () => {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_decrypt_fail_test.circom"));

        circuit.assertNotOut = async function(actualOut, expectedOut) {
            const self = this;
            if (!self.symbols) await self.loadSymbols();

            checkObject("main", expectedOut);

            function checkObject(prefix, eOut) {

                if (Array.isArray(eOut)) {
                    for (let i = 0; i < eOut.length; i++) {
                        checkObject(prefix + "[" + i + "]", eOut[i]);
                    }
                } else if ((typeof eOut == "object") && (eOut.constructor.name == "Object")) {
                    for (let k in eOut) {
                        checkObject(prefix + "." + k, eOut[k]);
                    }
                } else {
                    if (typeof self.symbols[prefix] == "undefined") {
                        assert(false, "Output variable not defined: " + prefix);
                    }
                    const ba = actualOut[self.symbols[prefix].varIdx].toString();
                    const be = eOut.toString();
                    assert.notEqual(ba, be, prefix);
                }
            }
        }.bind(circuit);

        const w = await circuit.calculateWitness({xL_in: 1, xR_in: 2, k: 3, k_two: 4});

        await circuit.assertNotOut(w, {xL_out: '1', xR_out: '2'});

        await circuit.checkConstraints(w);
    });

    it("Should check permutation", async () => {

        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_test.circom"));

        const w = await circuit.calculateWitness({xL_in: 1, xR_in: 2, k: 3});

        const out2 = mimcSponge.hash(1,2,3);

        await circuit.assertOut(w, {xL_out: F.toObject(out2.xL), xR_out: F.toObject(out2.xR)});

        await circuit.checkConstraints(w);

    });

    it("Should check hash", async () => {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "mimc_sponge_hash_test.circom"));

        const w = await circuit.calculateWitness({ins: [1, 2], k: 0});

        const out2 = mimcSponge.multiHash([1,2], 0, 3);

        for (let i=0; i<out2.length; i++) out2[i] = F.toObject(out2[i]);

        await circuit.assertOut(w, {outs: out2});

        await circuit.checkConstraints(w);
    });
});
