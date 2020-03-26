package sg.gov.ndi;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

class CertUtil {

	/**
	 * <p>
	 * Load KeyStore
	 * </p>
	 * 
	 * @param keyStoreDir
	 *            the keystore name
	 * @param keyStorePwd
	 *            the keystore password
	 * @return the keystore
	 * @since 1.0
	 */
	static KeyStore loadKeyStore(String keyStoreDir, String keyStorePwd) throws MyInfoException {

		KeyStore keystore = null;

		try (InputStream is = new FileInputStream(new File(keyStoreDir))) {
			keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(is, keyStorePwd.toCharArray());
		} catch (Exception e) {
			throw new MyInfoException();
		}

		return keystore;
	}

	/**
	 * <p>
	 * Get Private Key
	 * </p>
	 * 
	 * @param keystore
	 *            the keystore
	 * @param privateCert
	 *            the private certificate name
	 * @param privateKeyPwd
	 *            the private certificate password
	 * @return the private key
	 * @since 1.0
	 */
	static Key getAgencyPrivateKey(KeyStore keystore, String privateCert, String privateKeyPwd) throws MyInfoException {

		Key agencyPrivateKey = null;
		Enumeration<String> enumeration = null;

		// Iterate keystore to retrieve private keys
		try {
			enumeration = keystore.aliases();
		} catch (Exception e) {
			throw new MyInfoException();
		}
		while (enumeration != null && enumeration.hasMoreElements()) {
			String alias = enumeration.nextElement();
			if (alias.equals(privateCert))
				try {
					agencyPrivateKey = keystore.getKey(alias, privateKeyPwd.toCharArray());
				} catch (Exception e) {
					throw new MyInfoException();
				}
		}

		return agencyPrivateKey;
	}

	/**
	 * <p>
	 * Get Public Key
	 * </p>
	 * 
	 * @param publicCert
	 *            the public certificate
	 * @return the public key
	 * @since 1.0
	 */
	static RSAPublicKey getPublicKey(Certificate publicCert) throws MyInfoException {

		RSAPublicKey publicKey = null;

		if (publicCert != null) {
			publicKey = (RSAPublicKey) publicCert.getPublicKey();
		}

		return publicKey;
	}

	/**
	 * <p>
	 * Get Public Certificate
	 * </p>
	 * 
	 * @param keystore
	 *            the keystore
	 * @param publicCert
	 *            the public certificate name
	 * @return the public certificate
	 * @since 1.0
	 */
	static Certificate getPublicCert(KeyStore keystore, String publicCert) throws MyInfoException {

		Certificate authPublicCert = null;
		Enumeration<String> enumeration = null;

		// Iterate keystore to retrieve the public certificate
		try {
			enumeration = keystore.aliases();
		} catch (KeyStoreException e) {
			throw new MyInfoException();
		}
		while (enumeration != null && enumeration.hasMoreElements()) {
			String alias = enumeration.nextElement();
			if (alias.equals(publicCert))
				try {
					authPublicCert = keystore.getCertificate(alias);
				} catch (KeyStoreException e) {
					throw new MyInfoException();
				}
		}

		return authPublicCert;
	}

}
