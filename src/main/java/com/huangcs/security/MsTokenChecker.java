package com.huangcs.security;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.codec.binary.Base64;

/**
 * desc area
 * Created by yunBo on 2018/9/25 0025.
 * //keytool -genkey -alias omcIms -keypass abcABC -keyalg RSA -keysize 1024 -validity 3650 -keystore omcIms.jks -storepass abc@2018
 * -dname "CN=localhost,OU=localhost, O=localhost, L=WS, ST=WS, C=CN"
 */
public class MsTokenChecker {

	private static final int MAX_ENCRYPT_BLOCK = 117;
	private static final int MAX_DECRYPT_BLOCK = 128;

	private static final String SHA1WithRSA = "SHA1WithRSA";
	private static final String RSA = "RSA";

	private static final Map<String, Object> signData = new ConcurrentHashMap<>();
	private static final String CRRECEPAY_SIGN_X509CERTIFICATE = "omcIms_SIGN_X509CERTIFICATE";

	private static final String KEY_PASS = "abcABC";
	private static final String SOTRE_PASS = "abc@2018";
	private static final String ALIAS = "omcIms";
	private static final String JKS_FILE = "D:/omcIms.jks";
	private static final String PUB_FILE = "D:/omcIms.cer";

	private static void initX509Certificate(String cerFilePath)
			throws FileNotFoundException, IOException, CertificateException {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		try (InputStream inputStream = new FileInputStream(cerFilePath)) {
			X509Certificate x509Certificate = (X509Certificate) certificateFactory
					.generateCertificate(inputStream);
			signData.put(CRRECEPAY_SIGN_X509CERTIFICATE, x509Certificate);
		}
	}

	/**
	 * 获取私钥信息
	 * @param jksFilePath
	 * @param keyAlias
	 * @param keyPass
	 * @param storePass
	 * @return
	 * @throws Exception
	 */
	private static PrivateKey getPrivateKey(String jksFilePath, String keyAlias, String keyPass,
			String storePass) throws Exception {
		File jksFile = new File(jksFilePath);
		InputStream in = new FileInputStream(jksFile);
		return getPrivateKey(in, keyAlias, keyPass, storePass);
	}

	private static PrivateKey getPrivateKey(InputStream in, String keyAlias, String keyPass,
			String storePass) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(in, storePass.toCharArray());
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPass.toCharArray());
		return privateKey;
	}

	/**
	 * 获取公钥信息
	 * @param cerFilePath
	 * @return
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 */
	public static PublicKey getPublicKey(String cerFilePath)
			throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		PublicKey publicKey = null;
		X509Certificate x509Certificate = (X509Certificate) signData
				.get(CRRECEPAY_SIGN_X509CERTIFICATE);
		if (x509Certificate == null) {
			initX509Certificate(cerFilePath);
			x509Certificate = (X509Certificate) signData.get(CRRECEPAY_SIGN_X509CERTIFICATE);
		}
		publicKey = x509Certificate.getPublicKey();
		return publicKey;
	}

	/**
	 * 加密
	 * @param requestStr
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptContentBytes(String requestStr) throws Exception {

		try {
			PublicKey publicKey = getPublicKey(PUB_FILE);
			String pubKey = Base64.encodeBase64String(publicKey.getEncoded());
			byte[] content = encryptByPublicKey(requestStr.getBytes(), pubKey);
			return content;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 公钥加密
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {

		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		decryptData(data, cipher, inputLen, out, offSet, i, MAX_ENCRYPT_BLOCK);
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	private static void decryptData(byte[] data, Cipher cipher, int inputLen,
			ByteArrayOutputStream out, int offSet, int i, int maxEncryptBlock)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] cache;
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > maxEncryptBlock) {
				cache = cipher.doFinal(data, offSet, maxEncryptBlock);
			}
			else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * maxEncryptBlock;
		}
	}

	/**
	 * 私钥解密
	 *
	 * @param encryptedData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
			throws Exception {

		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		decryptData(encryptedData, cipher, inputLen, out, offSet, i, MAX_DECRYPT_BLOCK);
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 解密
	 * @param responseDataBytes
	 * @return
	 * @throws Exception
	 */
	public static String decryptContentBytes(byte[] responseDataBytes) throws Exception {

		try {
			PrivateKey privateKey = getPrivateKey(JKS_FILE, ALIAS, KEY_PASS, SOTRE_PASS);
			String priKey = Base64.encodeBase64String(privateKey.getEncoded());
			byte[] decryptContentBytes = decryptByPrivateKey(responseDataBytes, priKey);

			return new String(decryptContentBytes, "UTF-8");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 加签
	 * @param signData
	 * @return
	 * @throws Exception
	 */
	public static String sign(String signData) throws Exception {
		KeyStore keyStore = null;
		try (InputStream in = new FileInputStream(new File(JKS_FILE))) {
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(in, SOTRE_PASS.toCharArray());
		}
		// 获取jks证书别名
		Enumeration en = keyStore.aliases();
		String pName = null;
		while (en.hasMoreElements()) {
			String n = (String) en.nextElement();
			if (keyStore.isKeyEntry(n)) {
				pName = n;
			}
		}
		PrivateKey key = getPrivateKey(JKS_FILE, pName, KEY_PASS, SOTRE_PASS);
		Signature signature = Signature.getInstance(SHA1WithRSA);
		signature.initSign(key);
		signature.update(signData.getBytes("UTF-8"));
		byte[] signedData = signature.sign();
		String signDate = new String(new Base64().encode(signedData));
		signDate = signDate.replaceAll("\r\n", "").replaceAll("\n", "");
		return signDate;
	}

	/**
	 * 验签
	 * @return
	 * @throws Exception
	 */
	public static boolean verifySign2(String originData, String returnSignData) throws Exception {

		PublicKey publicKey = getPublicKey(PUB_FILE);
		Signature sign3 = Signature.getInstance(SHA1WithRSA);
		sign3.initVerify(publicKey);
		sign3.update(originData.getBytes("UTF-8"));
		return sign3.verify(new Base64().decode(returnSignData));
	}

	public static void main(String[] args) throws Exception {

		String originData = "hello,my data";
		System.out.println("========> encrypting");
		byte[] enData = encryptContentBytes(originData);
		String signData = sign(originData);
		System.out.println("========> sign data:" + signData);
		String deData = decryptContentBytes(enData);
		System.out.println("========> descrypted data:" + deData);
		boolean verifySign = verifySign2(originData, signData);
		System.out.println("========> verify result:" + verifySign);
	}
}