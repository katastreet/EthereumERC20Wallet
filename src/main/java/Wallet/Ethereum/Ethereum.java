package Wallet.Ethereum;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.spongycastle.util.encoders.Hex;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;

import Wallet.Cryptocurrency;
import Wallet.lib.ECKeyPair;


public class Ethereum implements Cryptocurrency{
	
	/**
	 * addresses are always hex without 0x prefix
	 */
	
	public static String WEB3_URL = "https://ropsten.infura.io/";
	private SecureRandom random = new SecureRandom();
	private final int seedSize  = 32;
    @Override
    public byte[] newSeed() {
    	
		byte[] seed = new byte[seedSize];
		random.nextBytes(seed);
		return seed;
    }

    @Override
    public byte[] newPrivateKey() {
    	 ECKeyPair keyPair = ECKeyPair.createNew(true);
    	 return keyPair.getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
    	 ECKeyPair keyPair = ECKeyPair.create(seed);
    	 return keyPair.getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        return new byte[0];
    }

    //returns 65 byte public key i.e 64 bytes and one 0x00
    @Override
    public byte[] publicKey(byte[] privateKey) {
    	ECKeyPair keyPair = ECKeyPair.create(privateKey);
    	return keyPair.getPublic();
        
    }
    
    
    //get address from public 
    public String getAddress(byte[] privateKey)
    {
    	Credentials node = Credentials.create(Hex.toHexString(privateKey));
    	return node.getAddress();
    }
    
  //gets 65 byte public key byte i.e 64 bytes and one 0x00
    public String getAddressP(byte[] publicKey) {
    	return Keys.getAddress(Hex.toHexString(publicKey));
    }
    
    /**
     * this blocks
     * get balace(biginteger) in wei (10^18 decimal places)
     * @param address ethereum address
     * @throws ExecutionException 
     * @throws InterruptedException 
     * 
     */
    public static BigInteger getBalance(String address) throws InterruptedException, ExecutionException {
    		Web3j web3j = Web3j.build(new HttpService(WEB3_URL));
			EthGetBalance ethGetBalance = web3j.ethGetBalance("0x" + address, DefaultBlockParameterName.LATEST).sendAsync().get();
			return ethGetBalance.getBalance();
    }
    
    
    /**
     * this blocks
     * privateKey and to is hex string without 0x prefix
     * @param privateKey
     * @param to
     * @param value is in ether
     * @return
     * @throws InterruptedException
     * @throws IOException
     * @throws TransactionException
     * @throws Exception
     */
    public static boolean transferEther(String privateKey, String to, BigDecimal value) throws InterruptedException, IOException, TransactionException, Exception {
    	
    	Web3j web3j = Web3j.build(new HttpService(WEB3_URL));
		Credentials node = Credentials.create(privateKey);
		
		TransactionReceipt transactionReceipt = Transfer.sendFunds(web3j, node, "0x" + to, value, Convert.Unit.ETHER).send(); 
		if(transactionReceipt.getBlockHash().isEmpty() == true) {
			System.out.println("failed transcation");
			return false;
		}
		else {
			System.out.println("sent:" + " from: " + transactionReceipt.getFrom()+ ":" + transactionReceipt.getTo());
			return true;
		}
    }
    
    
}
