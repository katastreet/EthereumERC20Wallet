package Wallet.Ethereum;

import org.spongycastle.asn1.sec.SECNamedCurves;

import Wallet.lib.KeyGenerator;

public class EthKeyGenerator extends KeyGenerator {
	public EthKeyGenerator() {
		super(SECNamedCurves.getByName("secp256k1"), "Ethereum seed");
	}
}
