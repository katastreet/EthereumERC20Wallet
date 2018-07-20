package Wallet.lib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.generators.SCrypt;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import Wallet.lib.exceptions.ValidationException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.List;

/**
 * BIP32 Comptabile Key generator.
 */
public class KeyGenerator {
	private static final Logger log = LoggerFactory.getLogger(KeyGenerator.class);

	protected static SecureRandom secureRandom = new SecureRandom();

	protected static final String SECURITY_PROVIDER = "SC";
	protected static final String HMAC_SHA512 = "HmacSHA512";

	protected static final byte[] xprv = new byte[] { 0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4 };
	protected static final byte[] xpub = new byte[] { 0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E };
	protected static final byte[] tprv = new byte[] { 0x04, (byte) 0x35, (byte) 0x83, (byte) 0x94 };
	protected static final byte[] tpub = new byte[] { 0x04, (byte) 0x35, (byte) 0x87, (byte) 0xCF };

	protected final byte[] SEED_PREFIX;
	protected final X9ECParameters CURVE_PARAMS;
	protected final ECDomainParameters CURVE;
	protected final ECDomainParameters DOMAIN;
	protected final ECKeyPair EC_KEY_PAIR_GENERATOR;

	protected static final String EXCEPTION_MESSAGE_UNLIKELY = "This is rather unlikely, but it did just happen";
	protected static final String EXCEPTION_MESSAGE_NO_PRIVATE_KEY = "Need private key for private generation";

	public KeyGenerator(X9ECParameters CURVE_PARAMS, String seed) {
		this.SEED_PREFIX = seed.getBytes();
		this.CURVE_PARAMS = CURVE_PARAMS;
		CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
				CURVE_PARAMS.getH());
		DOMAIN = new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());
		EC_KEY_PAIR_GENERATOR = new ECKeyPair();
	}

	public byte[] newSeed() {
		byte[] seed = new byte[32];
		secureRandom.nextBytes(seed);
		return seed;
	}

	public ExtendedKey createExtendedKey() {
		ECKeyPair key = createECKeyPair(true);
		byte[] chainCode = new byte[32];
		secureRandom.nextBytes(chainCode);
		return new ExtendedKey(key, chainCode, 0, 0, 0);
	}

	public ExtendedKey createExtendedKey(byte[] seed) throws ValidationException {
		try {
			Mac mac = Mac.getInstance(HMAC_SHA512, SECURITY_PROVIDER);
			SecretKey seedkey = new SecretKeySpec(SEED_PREFIX, HMAC_SHA512);
			mac.init(seedkey);
			byte[] lr = mac.doFinal(seed);
			byte[] l = Arrays.copyOfRange(lr, 0, 32);
			byte[] r = Arrays.copyOfRange(lr, 32, 64);
			BigInteger m = new BigInteger(1, l);
			if (m.compareTo(CURVE_PARAMS.getN()) >= 0) {
				throw new ValidationException(EXCEPTION_MESSAGE_UNLIKELY);
			}
			ECKeyPair keyPair = new ECKeyPair(l, true);
			return new ExtendedKey(keyPair, r, 0, 0, 0);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
			throw new ValidationException(e);
		}
	}

	public ExtendedKey createExtendedKeyFromPassphrase(String passphrase, byte[] encryptedBytes)
			throws ValidationException {
		try {
			byte[] key = SCrypt.generate(passphrase.getBytes("UTF-8"), SEED_PREFIX, 16384, 8, 8, 32);
			SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
			if (encryptedBytes.length == 32) {
				// asssume encryptedBytes is seed
				Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", SECURITY_PROVIDER);
				cipher.init(Cipher.DECRYPT_MODE, keyspec);
				return createExtendedKey(cipher.doFinal(encryptedBytes));
			} else {
				// assume encryptedBytes serialization of a key
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", SECURITY_PROVIDER);
				byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, 16);
				byte[] data = Arrays.copyOfRange(encryptedBytes, 16, encryptedBytes.length);
				cipher.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(iv));
				return parseExtendedKey(new String(cipher.doFinal(data)));
			}
		} catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new ValidationException(e);
		}
	}

	public ExtendedKey parseExtendedKey(String serialized) throws ValidationException {
		byte[] data = ByteUtils.fromBase58WithChecksum(serialized);
		if (data.length != 78) {
			throw new ValidationException("invalid extended key");
		}
		byte[] type = Arrays.copyOf(data, 4);
		boolean hasPrivate;
		if (Arrays.areEqual(type, xprv) || Arrays.areEqual(type, tprv)) {
			hasPrivate = true;
		} else if (Arrays.areEqual(type, xpub) || Arrays.areEqual(type, tpub)) {
			hasPrivate = false;
		} else {
			throw new ValidationException("invalid magic number for an extended key");
		}

		int depth = data[4] & 0xff;

		int parent = data[5] & 0xff;
		parent <<= 8;
		parent |= data[6] & 0xff;
		parent <<= 8;
		parent |= data[7] & 0xff;
		parent <<= 8;
		parent |= data[8] & 0xff;

		int sequence = data[9] & 0xff;
		sequence <<= 8;
		sequence |= data[10] & 0xff;
		sequence <<= 8;
		sequence |= data[11] & 0xff;
		sequence <<= 8;
		sequence |= data[12] & 0xff;

		byte[] chainCode = Arrays.copyOfRange(data, 13, 13 + 32);
		byte[] pubOrPriv = Arrays.copyOfRange(data, 13 + 32, data.length);
		ECKeyPair key;
		if (hasPrivate) {
			key = new ECKeyPair(new BigInteger(1, pubOrPriv), true);
		} else {
			key = new ECKeyPair(pubOrPriv, true);
		}
		return new ExtendedKey(key, chainCode, depth, parent, sequence);
	}

	public ExtendedKey publicExtendedKey(ExtendedKey privateExtendedKey) {
		ECKeyPair ecKeyPair = createPublicOnlyECKeyPair(privateExtendedKey.getMaster().getPublic(), true);
		return new ExtendedKey(ecKeyPair, privateExtendedKey.getChainCode(), 0, 0, 0);
	}

	public ECKeyPair createECKeyPair(boolean compressed) {
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
			publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
		} else {
			byte[] encoded = point.getEncoded(false);
			publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
		}

		return new ECKeyPair(privateKey, publicKey, compressed);
	}

	public ECKeyPair createECKeyPair(KeyPair keyPair) {
		BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
		BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();

		BigInteger privateKeyValue = privateKey.getD();

		// Ethereum does not use encoded public keys like bitcoin - see
		// https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm for
		// details
		// Additionally, as the first bit is a constant prefix (0x04) we ignore this
		// value
		byte[] publicKeyBytes = publicKey.getQ().getEncoded(false);
		BigInteger publicKeyValue = new BigInteger(1,
				java.util.Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));

		return new ECKeyPair(privateKeyValue, publicKeyValue);
	}

	public ECKeyPair createECKeyPair(BigInteger privateKey) {
		return new ECKeyPair(privateKey, Sign.publicKeyFromPrivate(privateKey));
	}

	public ECKeyPair createECKeyPair(BigInteger privateKey, boolean compressed) {
		return new ECKeyPair(privateKey, compressed);
	}

	public ECKeyPair createECKeyPair(byte[] privateKey) {
		return createECKeyPair(Numeric.toBigInt(privateKey));
	}

	public ECKeyPair createECKeyPair(byte[] privateKey, boolean compressed) {
		try {
			return new ECKeyPair(privateKey, compressed);
		} catch (ValidationException e) {
			log.error("Could not create ECKeyPair", e);
		}
		return null;
	}

	public ECKeyPair createPublicOnlyECKeyPair(byte[] pub, boolean compressed) {
		ECKeyPair keyPair = new ECKeyPair();
		keyPair.setCompressed(compressed);
		BigInteger pubKey = new BigInteger(1, java.util.Arrays.copyOfRange(pub, 0, pub.length));
		keyPair.setPublicKey(pubKey);
		return keyPair;
	}

	public class ExtendedKey {
		private final ECKeyPair master;
		private final byte[] chainCode;
		private final int depth;
		private final int parent;
		private final int sequence;

		public ExtendedKey(ECKeyPair key, byte[] chainCode, int depth, int parent, int sequence) {
			this.master = key;
			this.chainCode = chainCode;
			this.parent = parent;
			this.depth = depth;
			this.sequence = sequence;
		}

		public ExtendedKey() {
			ECKeyPair key = createECKeyPair(true);
			byte[] chainCode = new byte[32];
			secureRandom.nextBytes(chainCode);
			this.master = key;
			this.chainCode = chainCode;
			this.parent = 0;
			this.depth = 0;
			this.sequence = 0;
		}

		public ECKeyPair getMaster() {
			return master;
		}

		public byte[] getChainCode() {
			return Arrays.clone(chainCode);
		}

		public int getDepth() {
			return depth;
		}

		public int getParent() {
			return parent;
		}

		public int getSequence() {
			return sequence;
		}

		public int getFingerPrint() {
			int fingerprint = 0;
			byte[] address = master.getAddress();
			for (int i = 0; i < 4; ++i) {
				fingerprint <<= 8;
				fingerprint |= address[i] & 0xff;
			}
			return fingerprint;
		}

		public ECKeyPair getKey(int sequence) throws ValidationException {
			return generateKey(sequence).getMaster();
		}

		public ExtendedKey getChild(int sequence) throws ValidationException {
			ExtendedKey sub = generateKey(sequence);
			return new ExtendedKey(sub.getMaster(), sub.getChainCode(), sub.getDepth() + 1, getFingerPrint(), sequence);
		}

		public ExtendedKey getReadOnly() {
			ECKeyPair keyPair = createPublicOnlyECKeyPair(master.getPublic(), true);
			return new ExtendedKey(keyPair, chainCode, depth, parent, sequence);
		}

		public boolean isReadOnly() {
			return master.getPrivate() == null;
		}

		public ExtendedKey generateKey(int sequence) throws ValidationException {
			try {
				if ((sequence & 0x80000000) != 0 && master.getPrivate() == null) {
					throw new ValidationException(EXCEPTION_MESSAGE_NO_PRIVATE_KEY);
				}

				Mac mac = Mac.getInstance(HMAC_SHA512, SECURITY_PROVIDER);
				SecretKey key = new SecretKeySpec(chainCode, HMAC_SHA512);
				mac.init(key);

				byte[] extended;
				byte[] pub = master.getPublic();
				if ((sequence & 0x80000000) == 0) {
					extended = new byte[pub.length + 4];
					System.arraycopy(pub, 0, extended, 0, pub.length);
					extended[pub.length] = (byte) ((sequence >>> 24) & 0xff);
					extended[pub.length + 1] = (byte) ((sequence >>> 16) & 0xff);
					extended[pub.length + 2] = (byte) ((sequence >>> 8) & 0xff);
					extended[pub.length + 3] = (byte) (sequence & 0xff);
				} else {
					byte[] priv = master.getPrivate();
					extended = new byte[priv.length + 5];
					System.arraycopy(priv, 0, extended, 1, priv.length);
					extended[priv.length + 1] = (byte) ((sequence >>> 24) & 0xff);
					extended[priv.length + 2] = (byte) ((sequence >>> 16) & 0xff);
					extended[priv.length + 3] = (byte) ((sequence >>> 8) & 0xff);
					extended[priv.length + 4] = (byte) (sequence & 0xff);
				}
				byte[] lr = mac.doFinal(extended);
				byte[] l = Arrays.copyOfRange(lr, 0, 32);
				byte[] r = Arrays.copyOfRange(lr, 32, 64);

				BigInteger m = new BigInteger(1, l);
				if (m.compareTo(CURVE_PARAMS.getN()) >= 0) {
					throw new ValidationException(EXCEPTION_MESSAGE_UNLIKELY);
				}
				if (master.getPrivate() != null) {
					BigInteger k = m.add(new BigInteger(1, master.getPrivate())).mod(CURVE_PARAMS.getN());
					if (k.equals(BigInteger.ZERO)) {
						throw new ValidationException(EXCEPTION_MESSAGE_UNLIKELY);
					}
					return new ExtendedKey(new ECKeyPair(k, true), r, depth, parent, sequence);
				} else {
					ECPoint q = CURVE_PARAMS.getG().multiply(m).add(CURVE_PARAMS.getCurve().decodePoint(pub));
					if (q.isInfinity()) {
						throw new ValidationException(EXCEPTION_MESSAGE_UNLIKELY);
					}
					pub = q.getEncoded(true);
					return new ExtendedKey(createPublicOnlyECKeyPair(pub, true), r, depth, parent, sequence);
				}
			} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
				throw new ValidationException(e);
			}
		}

		public byte[] encrypt(String passphrase, boolean production) throws ValidationException {
			try {
				byte[] key = SCrypt.generate(passphrase.getBytes("UTF-8"), SEED_PREFIX, 16384, 8, 8, 32);
				SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", SECURITY_PROVIDER);
				cipher.init(Cipher.ENCRYPT_MODE, keyspec);
				byte[] iv = cipher.getIV();
				byte[] c = cipher.doFinal(serialize(production).getBytes());
				byte[] result = new byte[iv.length + c.length];
				System.arraycopy(iv, 0, result, 0, iv.length);
				System.arraycopy(c, 0, result, iv.length, c.length);
				return result;
			} catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchProviderException
					| NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
					| BadPaddingException e) {
				throw new ValidationException(e);
			}
		}

		public String serialize(boolean production) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			try {
				if (master.getPrivateKey() != null) {
					if (production) {
						out.write(xprv);
					} else {
						out.write(tprv);
					}
				} else {
					if (production) {
						out.write(xpub);
					} else {
						out.write(tpub);
					}
				}
				out.write(depth & 0xff);
				out.write((parent >>> 24) & 0xff);
				out.write((parent >>> 16) & 0xff);
				out.write((parent >>> 8) & 0xff);
				out.write(parent & 0xff);
				out.write((sequence >>> 24) & 0xff);
				out.write((sequence >>> 16) & 0xff);
				out.write((sequence >>> 8) & 0xff);
				out.write(sequence & 0xff);
				out.write(chainCode);
				if (master.getPrivateKey() != null) {
					out.write(0x00);
					out.write(master.getPrivate());
				} else {
					out.write(master.getPublic());
				}
			} catch (IOException e) {
				log.error("Error on serializing extended key", e);
			}
			return ByteUtils.toBase58WithChecksum(out.toByteArray());
		}

	}

	public class ECKeyPair {
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
				this.publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
			} else {
				byte[] encoded = point.getEncoded(false);
				this.publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
			}
		}

		public ECKeyPair(BigInteger privateKey, boolean compressed) {
			this.privateKey = privateKey;
			this.compressed = compressed;

			ECPoint point = CURVE.getG().multiply(privateKey);
			if (compressed) {
				byte[] encoded = point.getEncoded(true);
				this.publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
			} else {
				byte[] encoded = point.getEncoded(false);
				this.publicKey = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 0, encoded.length));
			}
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
				System.arraycopy(p, Math.max(0, p.length - 32), tmp, Math.max(0, 32 - p.length),
						Math.min(32, p.length));
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

		public boolean verify(byte[] hash, byte[] signature, byte[] pub) {
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

}
