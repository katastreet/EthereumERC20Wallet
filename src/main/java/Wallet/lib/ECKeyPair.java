package Wallet.lib;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.math.ec.ECPoint;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import Wallet.lib.exceptions.ValidationException;

public class ECKeyPair {
	private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
	static final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(),
			CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
	private static final ECDomainParameters DOMAIN = new ECDomainParameters(CURVE.getCurve(), CURVE.getG(),
			CURVE.getN(), CURVE.getH());
	private static final SecureRandom secureRandom = new SecureRandom();

	private BigInteger privateKey;
	private BigInteger publicKey;
	private boolean compressed;

	public ECKeyPair() {
		this.privateKey = null;
		this.publicKey = null;
		this.compressed = false;
	}

	public ECKeyPair(BigInteger privateKey, BigInteger publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.compressed = false;
	}

	public ECKeyPair(BigInteger privateKey, BigInteger publicKey, boolean compressed) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.compressed = compressed;
	}

	public ECKeyPair(byte[] p, boolean compressed) throws ValidationException {
		if (p.length != 32) {
			throw new ValidationException("Invalid private key");
		}
		this.privateKey = new BigInteger(1, p).mod(CURVE.getN());
		this.compressed = compressed;

		ECPoint point = CURVE.getG().multiply(privateKey);
		if (compressed) {
			byte[] encoded = point.getEncoded(true);
			this.publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		} else {
			byte[] encoded = point.getEncoded(false);
			this.publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		}

	}

	public ECKeyPair(BigInteger privateKey, boolean compressed) {
		this.privateKey = privateKey;
		this.compressed = compressed;

		ECPoint point = CURVE.getG().multiply(privateKey);
		if (compressed) {
			byte[] encoded = point.getEncoded(true);
			this.publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		} else {
			byte[] encoded = point.getEncoded(false);
			this.publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		}
	}

	public static ECKeyPair publicOnly(byte[] pub, boolean compressed) {
		ECKeyPair keyPair = new ECKeyPair();
		keyPair.setCompressed(compressed);
		BigInteger pubKey = new BigInteger(1, Arrays.copyOfRange(pub, 0, pub.length));
		keyPair.setPublicKey(pubKey);
		return keyPair;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(BigInteger privateKey) {
		this.privateKey = privateKey;
	}

	public BigInteger getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(BigInteger publicKey) {
		this.publicKey = publicKey;
	}

	public void setCompressed(boolean compressed) {
		this.compressed = compressed;
	}

	public boolean isCompressed() {
		return this.compressed;
	}

	public static ECKeyPair createNew(boolean compressed) {
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(DOMAIN, secureRandom);
		generator.init(keygenParams);
		AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
		ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
		ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();

		BigInteger privateKey = privParams.getD();
		BigInteger publicKey;
		ECPoint point = CURVE.getG().multiply(privateKey);
		if (compressed) {
			byte[] encoded = point.getEncoded(true);
			publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		} else {
			byte[] encoded = point.getEncoded(false);
			publicKey = new BigInteger(1, Arrays.copyOfRange(encoded, 0, encoded.length));
		}

		ECKeyPair keyPair = new ECKeyPair(privateKey, publicKey, compressed);
		return keyPair;
	}

	public static ECKeyPair create(KeyPair keyPair) {
		BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
		BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();

		BigInteger privateKeyValue = privateKey.getD();

		// Ethereum does not use encoded public keys like bitcoin - see
		// https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm for
		// details
		// Additionally, as the first bit is a constant prefix (0x04) we ignore this
		// value
		byte[] publicKeyBytes = publicKey.getQ().getEncoded(false);
		BigInteger publicKeyValue = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

		return new ECKeyPair(privateKeyValue, publicKeyValue);
	}

	public static ECKeyPair create(BigInteger privateKey) {
		return new ECKeyPair(privateKey, Sign.publicKeyFromPrivate(privateKey));
	}

	public static ECKeyPair create(byte[] privateKey) {
		return create(Numeric.toBigInt(privateKey));
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		ECKeyPair ECKeyPair = (ECKeyPair) o;

		if (privateKey != null ? !privateKey.equals(ECKeyPair.privateKey) : ECKeyPair.privateKey != null) {
			return false;
		}

		return publicKey != null ? publicKey.equals(ECKeyPair.publicKey) : ECKeyPair.publicKey == null;
	}

	@Override
	public int hashCode() {
		int result = privateKey != null ? privateKey.hashCode() : 0;
		result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
		return result;
	}

	public byte[] getPrivate() {
		if (privateKey == null)
			return null;

		byte[] p = privateKey.toByteArray();
		if (p.length != 32) {
			byte[] tmp = new byte[32];
			System.arraycopy(p, Math.max(0, p.length - 32), tmp, Math.max(0, 32 - p.length), Math.min(32, p.length));
			p = tmp;
		}
		return p;
	}

	public byte[] getPublic() {
		return publicKey.toByteArray();
	}

	public byte[] getAddress() {
		return ByteUtils.keyHash(getPublic());
	}

	public byte[] sign(byte[] hash) throws ValidationException {
		if (privateKey == null) {
			throw new ValidationException("Need private key to sign");
		}
		ECDSASigner signer = new ECDSASigner();
		signer.init(true, new ECPrivateKeyParameters(privateKey, DOMAIN));
		BigInteger[] signature = signer.generateSignature(hash);
		ByteArrayOutputStream s = new ByteArrayOutputStream();
		try {
			DERSequenceGenerator seq = new DERSequenceGenerator(s);
			seq.addObject(new ASN1Integer(signature[0]));
			seq.addObject(new ASN1Integer(signature[1]));
			seq.close();
			return s.toByteArray();
		} catch (IOException e) {
			throw new ValidationException(e);
		}
	}

	public boolean verify(byte[] hash, byte[] signature) {
		return verify(hash, signature, getPublic());
	}

	public static boolean verify(byte[] hash, byte[] signature, byte[] pub) {
		ASN1InputStream asn1 = new ASN1InputStream(signature);
		try {
			ECDSASigner signer = new ECDSASigner();
			signer.init(false, new ECPublicKeyParameters(CURVE_PARAMS.getCurve().decodePoint(pub), DOMAIN));

			DLSequence seq = (DLSequence) asn1.readObject();
			BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
			BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
			return signer.verifySignature(hash, r, s);
		} catch (Exception e) {
			// treat format errors as invalid signatures
			return false;
		} finally {
			try {
				asn1.close();
			} catch (IOException e) {
			}
		}
	}

}
