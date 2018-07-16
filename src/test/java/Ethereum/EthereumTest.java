package Ethereum;

import static org.junit.Assert.*;

import org.ethereum.crypto.ECKey;
import org.spongycastle.util.encoders.Hex;

import Wallet.Ethereum.Ethereum;

import java.math.BigInteger;
import java.util.concurrent.ExecutionException;


import org.junit.Test;

public class EthereumTest {

		Ethereum ethereum = new Ethereum();

		@Test
		public void testAddress() {

//			PrivateKey key and address Generated using
//			byte[] privateKey = ethereum.newPrivateKey();
//			System.out.println(Hex.toHexString(privateKey));
//			
//			System.out.println(ethereum.getAddress(ethereum.publicKey(privateKey)));
			//also tested using the online address generator

			String privateKeyHex="56626d7f25c166335fb07985e8aaa5b2396661a2d9a11c0937601cc388f60032";
			String addressEthereum = "54f8ca535bfc5a5f9fdc29ee82c115532322180b";
			
			
			ECKey key = ECKey.fromPrivate(new BigInteger(privateKeyHex, 16));
			String computedAddress = Hex.toHexString(key.getAddress());
			
			byte[] privateKey = ethereum.newPrivateKey();
			String privateKeyH = Hex.toHexString(privateKey);
			
			System.out.println(privateKeyH);
			System.out.println(ethereum.getAddress(privateKey));
			
		
			assertEquals(addressEthereum, computedAddress);
			
		}
		
		@Test
		public void testSeed() {
			// seed 32 bytes
			// see if this seed produces same address twice
			byte[] seed = "abcdefghijklmnopqrstuvwxyz123454".getBytes();
			//twice generating address with same seed
			assertEquals(ethereum.getAddress(ethereum.publicKey(ethereum.newPrivateKey(seed))), ethereum.getAddress(ethereum.publicKey(ethereum.newPrivateKey(seed))));
		}
		
		@Test
		public void randomnessTest() {
			assertNotEquals(ethereum.getAddress(ethereum.publicKey(ethereum.newPrivateKey())), ethereum.getAddress(ethereum.publicKey(ethereum.newPrivateKey())));
			
		}
		
		@Test
		public void balanceTest() throws InterruptedException, ExecutionException {
			String addressEthereum = "05bf745a7a68b211c177addf6c5f71efc570d946";
			assertEquals(Ethereum.getBalance(addressEthereum), BigInteger.valueOf(0));	
		}

	}

