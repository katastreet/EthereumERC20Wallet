package Wallet;

import java.io.IOException;
import java.math.BigDecimal;

import org.web3j.protocol.exceptions.TransactionException;

import Wallet.Ethereum.Ethereum;


public class Main {
	public static void main(String[] args){
		try {
			System.out.println(Ethereum.transferEther("d81187f450077dd643309e00bc332c29fc5f695fb950ae6427f03e7f3ad9883a", "05bf745a7a68b211c177addf6c5f71efc570d946", BigDecimal.valueOf(0.2)));
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransactionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
