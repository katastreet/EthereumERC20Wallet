package Wallet.ERC20;

public class Main {
	public static void main(String[] args) {
		ERC20Wallet erc20Wallet = new ERC20Wallet("d81187f450077dd643309e00bc332c29fc5f695fb950ae6427f03e7f3ad9883a", "acf6525f8aa189d915298f56fc6632f1f6bd3ec0");
		
		try {
			System.out.println(erc20Wallet.getBalance("0a1a435a1f2d8aecf659b40cf63913881eb2a62f"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
