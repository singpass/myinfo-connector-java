package sg.gov.ndi;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;

public class MyInfoSecurityHelper {

	/**
	 * <p>
	 * Generate Signature Method
	 * </p>
	 * 
	 * @param the
	 *            formulated basestring
	 * @return the signature generated from the basestring and the private key
	 * @see <a
	 *      href="https://www.ndi-api.gov.sg/library/trusted-data/myinfo/tools-signatureverifier</a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	public static String generateSignature(String baseString, Key myinfoPrivateKey) throws MyInfoException {

		String signedBaseString = null;

		try {

			if (myinfoPrivateKey != null) {
				Signature sign = Signature.getInstance("SHA256withRSA");
				sign.initSign((PrivateKey) myinfoPrivateKey);
				sign.update(baseString.getBytes());
				signedBaseString = Base64.getEncoder().encodeToString(sign.sign());
			}
		} catch (Exception e) {
			throw new MyInfoException();
		}
		return signedBaseString;
	}

	/**
	 * <p>
	 * Generate Base String Method
	 * </p>
	 * 
	 * @param httpMethod
	 *            the method
	 * @param apiURL
	 *            the api url
	 * @param baseParams
	 *            a map collection that include the client id, app id, nonce,
	 *            signature, signature method, timestamp, etc. that is required
	 *            to generate the token and person's basestring.
	 * @return the formulated basestring
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/tools-basestringchecker"></a>
	 * @since 1.0
	 */
	public static String generateBaseString(String httpMethod, String apiURL, TreeMap<String, String> baseParams) {

		StringBuilder strParams = new StringBuilder();
		String baseString = null;

		for (Map.Entry<String, String> entry : baseParams.entrySet()) {
			strParams.append("&");
			strParams.append(entry.getKey());
			strParams.append(entry.getValue());
		}

		baseString = httpMethod + "&" + apiURL + strParams.toString();

		return baseString;
	}

	/**
	 * <p>
	 * Generate Authorization Header Method
	 * </p>
	 * 
	 * @param defaultHeader
	 *            a map collection that include the app id, nonce, signature,
	 *            signature method, timestamp, etc. that is required by the
	 *            token and person's authorization header.
	 * @param bearer
	 *            bearer token
	 * @return the formulated token authorization header
	 * @since 1.0
	 */
	public static String generateAuthorizationHeader(TreeMap<String, String> defaultHeader, String bearer) {

		StringBuilder strParam = new StringBuilder();
		String authHeader = null;

		for (Map.Entry<String, String> entry : defaultHeader.entrySet()) {
			strParam.append(entry.getKey());
			strParam.append("\"");
			strParam.append(entry.getValue());
			strParam.append("\",");
		}

		String strParams = strParam.toString().substring(0, strParam.length() - 1);

		if (bearer != null) {
			authHeader = ApplicationConstant.PKI_SIGN + " " + strParam + "," + ApplicationConstant.BEARER + " "
					+ bearer;
		} else {
			authHeader = ApplicationConstant.PKI_SIGN + " " + strParams;
		}

		return authHeader;
	}

	/**
	 * <p>
	 * Generate Authorization Header Method
	 * </p>
	 * 
	 * @param defaultHeader
	 *            a map collection that include the app id, nonce, signature,
	 *            signature method, timestamp, etc. that is required by the
	 *            token and person's authorization header.
	 * @return the formulated token authorization header
	 * @since 1.0
	 */
	public static String generateAuthorizationHeader(TreeMap<String, String> defaultHeader) {
		return generateAuthorizationHeader(defaultHeader, null);
	}

	/**
	 * <p>
	 * get Payload Method
	 * </p>
	 * 
	 * <p>
	 * Decrypt and retrieve payload returned from the Person API call
	 * </p>
	 *
	 * @param result
	 *            the returned encrypted result
	 * @param privateKey
	 *            the private key
	 * @return the decrypted payload
	 * @since 1.0
	 */
	public static String getPayload(String result, Key privateKey) throws MyInfoException {

		JWEDecrypter decrypter = new RSADecrypter((PrivateKey) privateKey);
		EncryptedJWT encryptedJWT;
		try {
			encryptedJWT = EncryptedJWT.parse(result);
			encryptedJWT.decrypt(decrypter);
		} catch (Exception e) {
			throw new MyInfoException();
		}
		// Get String Payload
		String getPayLoad = encryptedJWT.getPayload().toString();
		// Remove inverted commas from payload string
		String payload = getPayLoad.substring(1, getPayLoad.length() - 1);

		return payload;
	}

	/**
	 * <p>
	 * Verify Token Method
	 * </p>
	 * 
	 * @param decryptedPayload
	 *            the decrypted payload
	 * @param pubKey
	 *            the public key
	 * @return the verified token
	 * @since 1.0
	 */
	public static DecodedJWT verifyToken(String decryptedPayload, RSAPublicKey pubKey) throws MyInfoException {

		DecodedJWT personJWT;

		Algorithm algo = Algorithm.RSA256(pubKey);
		JWTVerifier verifier = JWT.require(algo).acceptLeeway(300).build();

		try {
			personJWT = verifier.verify(decryptedPayload);

		} catch (Exception e) {
			throw new MyInfoException();
		}
		return personJWT;
	}

}
