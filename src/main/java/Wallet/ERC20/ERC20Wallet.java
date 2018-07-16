package Wallet.ERC20;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;



public class ERC20Wallet {
	public static String WEB3_URL = "https://ropsten.infura.io/";
	public static final BigInteger GAS_PRICE = ERC20Interface.GAS_PRICE;
	public static final BigInteger GAS_LIMIT = ERC20Interface.GAS_LIMIT;
	public static long decimalDigits= 1000000000000000000L;
	public ERC20Interface erc20Interface;
	
	
	/***
	 * 
	 * @param privateKey hex string without 0x
	 * @param deployedAddress sting with 0x
	 */
	public ERC20Wallet(String privateKey, String deployedAddress) {
		Web3j web3j = Web3j.build(new HttpService(WEB3_URL));
		Credentials node = Credentials.create(privateKey);
		
		
		erc20Interface = ERC20Interface.load("0x" + deployedAddress, web3j, node, GAS_PRICE, GAS_LIMIT);
		
		
		
	}
	
	public boolean Transfer(String to, BigDecimal amount) throws Exception {
		BigInteger token_amount = amount.multiply(BigDecimal.valueOf(decimalDigits)).toBigInteger();
		System.out.println(token_amount);
		
		TransactionReceipt tx = erc20Interface.transfer("0x"+to ,token_amount).send();
		
		if(tx.getBlockHash().isEmpty() == true) {
			System.out.println("failed transcation");
			return false;
		}
		else {
			System.out.println("from: " + tx.getFrom()+ " to :" + tx.getTo());
			return true;
		}
		
	}
	
	// returns the balance in wei like
	/**
	 * 
	 * @param address
	 * @return
	 * @throws Exception
	 */
	public BigInteger amount(String address) throws Exception {
		BigInteger valueOf = erc20Interface.balanceOf("0x" +address).send();
		return valueOf;
	}

}
