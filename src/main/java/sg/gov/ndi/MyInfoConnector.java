package sg.gov.ndi;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.TreeMap;

import javax.net.ssl.HttpsURLConnection;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * <p>
 * This is the main class of the MyInfoConnector
 * </p>
 * <p>
 * This connector aims to simplify consumer’s integration effort with MyInfo by
 * providing an easy to use functions
 * </p>
 * 
 * @see <a href=
 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/introduction"></a>
 * @since 1.0
 */
public class MyInfoConnector {

	private String keyStoreDir;
	private String keyStorePwd;
	private String privateCert;
	private String publicCert;
	private String privateKeyPwd;
	private String clientAppId;
	private String clientAppPwd;
	private String spEsvcId;
	private String redirectUri;
	private String attributes;
	private String env;
	private String tokenURL;
	private String personURL;
	private String proxyTokenURL;
	private String proxyPersonURL;
	private String useProxy;

	private static MyInfoConnector instance;

	// Private constructor to avoid client applications to use constructor
	private MyInfoConnector(String propPath) throws MyInfoException {
		Properties prop = null;
		try (InputStream input = new FileInputStream(propPath)) {
			prop = new Properties();
			prop.load(input);
			load(prop);
		} catch (IOException e) {
			throw new MyInfoException();
		}

	}

	// Return current instance
	public static MyInfoConnector getCurrentInstance() throws MyInfoException {
		if (instance == null) {
			throw new MyInfoException("No instance has been initialized.");
		}
		return instance;
	}

	// Create singleton
	public static MyInfoConnector getInstance(String propPath) throws MyInfoException {
		if (instance == null) {
			instance = new MyInfoConnector(propPath);
		} else {
			throw new MyInfoException("Instance has been initialized. Please get the current instance.");
		}
		return instance;
	}

	/**
	 * <p>
	 * Load Properties File
	 * </p>
	 * <p>
	 * This function loads the properties file into MyInfoConnector class
	 * variables.
	 * </p>
	 * 
	 * @param prop
	 *            the absolute path of the properties file
	 * @since 1.0
	 * @throws MyInfoException
	 */
	private void load(Properties prop) throws MyInfoException {

		if (StringUtil.isEmptyAndNull(prop.getProperty("KEYSTORE"))) {
			throw new MyInfoException("KeyStore value not found or empty in properties file!");
		} else {
			this.keyStoreDir = prop.getProperty("KEYSTORE");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("KEYSTORE_PASSPHRASE"))) {
			throw new MyInfoException("KeyStore pass phrase not found or empty in properties file!");
		} else {
			this.keyStorePwd = prop.getProperty("KEYSTORE_PASSPHRASE");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("PRIVATE_KEY_ALIAS"))) {
			throw new MyInfoException("Private key alias not found or empty in properties file!");
		} else {
			this.privateCert = prop.getProperty("PRIVATE_KEY_ALIAS");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("PUBLIC_CERT_ALIAS"))) {
			throw new MyInfoException("Public cert not found or empty in properties file!");
		} else {
			this.publicCert = prop.getProperty("PUBLIC_CERT_ALIAS");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("KEYSTORE_PRIVATE_KEY_PASSPHRASE"))) {
			throw new MyInfoException("KeyStore private key not found or empty in properties file!");
		} else {
			this.privateKeyPwd = prop.getProperty("KEYSTORE_PRIVATE_KEY_PASSPHRASE");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("CLIENT_ID"))) {
			throw new MyInfoException("Client id not found or empty in properties file!");
		} else {
			this.clientAppId = prop.getProperty("CLIENT_ID");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("CLIENT_SECRET"))) {
			throw new MyInfoException("Client secret not found or empty in properties file!");
		} else {
			this.clientAppPwd = prop.getProperty("CLIENT_SECRET");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("SP_ESERVICES_ID"))) {
			throw new MyInfoException("eService Id not found or empty in properties file!");
		} else {
			this.spEsvcId = prop.getProperty("SP_ESERVICES_ID");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("REDIRECT_URL"))) {
			throw new MyInfoException("Redirect url not found or empty in properties file!");
		} else {
			this.redirectUri = prop.getProperty("REDIRECT_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("ATTRIBUTES"))) {
			throw new MyInfoException("Attributes not found or empty in properties file!");
		} else {
			this.attributes = prop.getProperty("ATTRIBUTES");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("ENVIRONMENT"))) {
			throw new MyInfoException("Environment not found or empty in properties file!");
		} else {
			this.env = prop.getProperty("ENVIRONMENT");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("TOKEN_URL"))) {
			throw new MyInfoException("Token url not found or empty in properties file!");
		} else {
			this.tokenURL = prop.getProperty("TOKEN_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("PERSON_URL"))) {
			throw new MyInfoException("Person url not found or empty in properties file!");
		} else {
			this.personURL = prop.getProperty("PERSON_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("USE_PROXY"))) {
			throw new MyInfoException("Use proxy indicator not found or empty in properties file!");
		} else {
			this.useProxy = prop.getProperty("USE_PROXY");
			if (this.useProxy.equals(ApplicationConstant.YES)) {
				if (StringUtil.isEmptyAndNull(prop.getProperty("PROXY_TOKEN_URL"))) {
					throw new MyInfoException("Proxy token url not found or empty in properties file!");
				} else {
					this.proxyTokenURL = prop.getProperty("PROXY_TOKEN_URL");
				}
				if (StringUtil.isEmptyAndNull(prop.getProperty("PROXY_PERSON_URL"))) {
					throw new MyInfoException("Proxy person url not found or empty in properties file!");
				} else {
					this.proxyPersonURL = prop.getProperty("PROXY_PERSON_URL");
				}
			}
		}
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function takes in all the required variables, invoke the
	 * getAccessToken API to generate the access token. The access token is then
	 * use to invoke the person API to get the Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code
	 * @param txnNo
	 *            the transaction no required in person call
	 * @param state
	 *            the state required in token call
	 * @param publicCert
	 *            the public cert
	 * @param privateKey
	 *            the private key
	 * @param clientAppId
	 *            the client id
	 * @param clientAppPwd
	 *            the client password
	 * @param redirectUri
	 *            the redirect url
	 * @param attributes
	 *            the attributes
	 * @param env
	 *            the environment
	 * @param tokenUrl
	 *            the token url
	 * @param personUrl
	 *            the person url
	 * @param proxyTokenURL
	 *            user provided proxy url
	 * @param proxyPersonURL
	 *            user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getMyInfoPersonData(String authCode, String txnNo, String state, Certificate publicCert,
			Key privateKey, String clientAppId, String clientAppPwd, String redirectUri, String attributes,
			String env, String tokenURL, String personURL, String proxyTokenURL, String proxyPersonURL, String useProxy, String spEsvcId)
			throws MyInfoException {

		String result = null;
		String jsonResponse = null;

		RSAPublicKey pubKey = CertUtil.getPublicKey(publicCert);

		// Get access token
		String token = MyInfoConnector.getAccessToken(authCode, tokenURL, clientAppId, clientAppPwd, redirectUri, env,
				privateKey, state, proxyTokenURL, useProxy);

		HashMap<String, String> tokenList = new Gson().fromJson(token, new TypeToken<HashMap<String, String>>() {
		}.getType());
		DecodedJWT tokenJWT = MyInfoSecurityHelper.verifyToken(tokenList.get(ApplicationConstant.ACCESS_TOKEN), pubKey);

		// Get person
		result = MyInfoConnector.getPersonData(tokenJWT.getSubject(), tokenList.get(ApplicationConstant.ACCESS_TOKEN),
				txnNo, personURL, clientAppId, attributes, env, privateKey, proxyPersonURL, useProxy, spEsvcId);

		if (!env.equalsIgnoreCase(ApplicationConstant.SANDBOX)) {

			try {
				String payload = MyInfoSecurityHelper.getPayload(result, privateKey);
				DecodedJWT personJWT = MyInfoSecurityHelper.verifyToken(payload, pubKey);

				// Convert byte[] to String
				byte[] base64Decode = Base64.getDecoder().decode(personJWT.getPayload());
				jsonResponse = new String(base64Decode);

			} catch (Exception e) {
				throw new MyInfoException();
			}
		} else {
			jsonResponse = result;
		}
		return jsonResponse;
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function will takes in a keystore, retrieve all the properties value
	 * from the class variable and call the main static getMyInfoPersonData
	 * function to retrieve MyInfo Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code
	 * @param txnNo
	 *            the transaction no required in person call
	 * @param state
	 *            the state required in token call
	 * @param keyStoreDir
	 *            the keystore absolute path
	 * @param keyStorePwd
	 *            the keystore password
	 * @param privateCert
	 *            name of the private cert
	 * @param publicCert
	 *            name of the public cert
	 * @param privateKeyPwd
	 *            the private key password
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected String getMyInfoPersonData(String authCode, String txnNo, String state, String keyStoreDir,
			String keyStorePwd, String privateCert, String publicCert, String privateKeyPwd) throws MyInfoException {

		KeyStore keystore = CertUtil.loadKeyStore(keyStoreDir, keyStorePwd);
		Key agencyPrivateKey = CertUtil.getAgencyPrivateKey(keystore, privateCert, privateKeyPwd);
		Certificate myInfoPublicCert = CertUtil.getPublicCert(keystore, publicCert);

		return getMyInfoPersonData(authCode, txnNo, state, myInfoPublicCert, agencyPrivateKey, this.clientAppId,
				this.clientAppPwd, this.redirectUri, this.attributes, this.env, this.tokenURL, this.personURL,
				this.proxyTokenURL, this.proxyPersonURL, this.useProxy, this.spEsvcId);
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function will retrieve all the properties value from the class
	 * variable and call the static getMyInfoPersonData function to retrieve
	 * MyInfo Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code (authCode)
	 * @param txnNo
	 *            the transaction no
	 * @param state
	 *            the state required in token call
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	public String getMyInfoPersonData(String authCode, String txnNo, String state) throws MyInfoException {
		return getMyInfoPersonData(authCode, txnNo, state, this.keyStoreDir, this.keyStorePwd, this.privateCert,
				this.publicCert, this.privateKeyPwd);
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function will retrieve all the properties value from the class
	 * variable and call the static getMyInfoPersonData function to retrieve
	 * MyInfo Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code (authCode)
	 * @param state
	 *            the state required in token call
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	public String getMyInfoPersonData(String authCode, String state) throws MyInfoException {
		return getMyInfoPersonData(authCode, state, this.keyStoreDir, this.keyStorePwd, this.privateCert,
				this.publicCert, this.privateKeyPwd);
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function will retrieve all the properties value from the class
	 * variable and call the static getMyInfoPersonData function to retrieve
	 * MyInfo Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code (authCode)
	 * @param state
	 *            the state required in token call
	 * @param keyStoreDir
	 *            the keystore absolute path
	 * @param keyStorePwd
	 *            the keystore password
	 * @param privateCert
	 *            name of the private cert
	 * @param publicCert
	 *            name of the public cert
	 * @param privateKeyPwd
	 *            the private key password
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected String getMyInfoPersonData(String authCode, String state, String keyStoreDir, String keyStorePwd,
			String privateCert, String publicCert, String privateKeyPwd) throws MyInfoException {
		return getMyInfoPersonData(authCode, null, state, keyStoreDir, keyStorePwd, privateCert, publicCert,
				privateKeyPwd);
	}

	/**
	 * <p>
	 * Get Authorization(Access) Token
	 * </p>
	 * <p>
	 * This API is invoked by your application server to obtain an "access
	 * token", which can be used to call the Person API for the actual data.
	 * Your application needs to provide a valid "authorisation code" from the
	 * authorise API in exchange for the "access token".
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code
	 * @param apiURL
	 *            the api url
	 * @param clientAppId
	 *            the client app id
	 * @param clientAppPwd
	 *            the client secret
	 * @param redirectUri
	 *            the redirect url
	 * @param env
	 *            the environment
	 * @param myinfoPrivateKey
	 *            the private key
	 * @param state
	 *            the state required in token call
	 * @param proxyTokenURL
	 *            user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the access token
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/oauth"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getAccessToken(String authCode, String apiURL, String clientAppId, String clientAppPwd,
			String redirectUri, String env, Key myinfoPrivateKey, String state, String proxyTokenURL, String useProxy)
			throws MyInfoException {

		StringBuilder result = new StringBuilder();

		try {
			String cacheCtl = ApplicationConstant.NO_CACHE;
			String method = ApplicationConstant.POST_METHOD;
			int nonceValue = new SecureRandom().nextInt();
			nonceValue = Math.abs(nonceValue);
			long timestamp = new Date().getTime();

			String authHeader = null;
			String signature = null;

			String userInputURL = useProxy.equals(ApplicationConstant.YES) ? proxyTokenURL : apiURL;

			// A) Forming the Signature Base String
			TreeMap<String, String> baseParams = new TreeMap<>();
			baseParams.put(ApplicationConstant.APP_ID + "=", clientAppId);
			baseParams.put(ApplicationConstant.CLIENT_ID + "=", clientAppId);
			baseParams.put(ApplicationConstant.CLIENT_SECRET + "=", clientAppPwd);
			baseParams.put(ApplicationConstant.CODE + "=", authCode);
			baseParams.put(ApplicationConstant.GRANT_TYPE + "=", ApplicationConstant.AUTHORIZATION_CODE);
			baseParams.put(ApplicationConstant.NONCE + "=", Integer.toString(nonceValue));
			baseParams.put(ApplicationConstant.REDIRECT_URI + "=", redirectUri);
			baseParams.put(ApplicationConstant.SIGNATURE_METHOD + "=", ApplicationConstant.RS256);
			baseParams.put(ApplicationConstant.TIMESTAMP + "=", Long.toString(timestamp));
			baseParams.put(ApplicationConstant.STATE + "=", state);

			String baseString = MyInfoSecurityHelper.generateBaseString(ApplicationConstant.POST_METHOD, apiURL,
					baseParams);

			if (!env.equalsIgnoreCase(ApplicationConstant.SANDBOX)) {

				// B) Signing Base String to get Digital Signature
				if (baseString != null) {
					signature = MyInfoSecurityHelper.generateSignature(baseString, myinfoPrivateKey);
				}

				// C) Assembling the Header
				if (signature != null) {
					TreeMap<String, String> authHeaderParams = new TreeMap<>();
					authHeaderParams.put(ApplicationConstant.APP_ID + "=", clientAppId);
					authHeaderParams.put(ApplicationConstant.NONCE + "=", Integer.toString(nonceValue));
					authHeaderParams.put(ApplicationConstant.SIGNATURE_METHOD + "=", ApplicationConstant.RS256);
					authHeaderParams.put(ApplicationConstant.SIGNATURE + "=", signature);
					authHeaderParams.put(ApplicationConstant.TIMESTAMP + "=", Long.toString(timestamp));
					authHeader = MyInfoSecurityHelper.generateAuthorizationHeader(authHeaderParams);
				}

			}

			// D) Assembling the params
			StringBuilder params = new StringBuilder();

			params.append(ApplicationConstant.GRANT_TYPE).append("=").append(ApplicationConstant.AUTHORIZATION_CODE)
					.append("&").append(ApplicationConstant.CODE).append("=").append(authCode).append("&")
					.append(ApplicationConstant.REDIRECT_URI).append("=").append(redirectUri).append("&")
					.append(ApplicationConstant.CLIENT_ID).append("=").append(clientAppId).append("&")
					.append(ApplicationConstant.CLIENT_SECRET).append("=").append(clientAppPwd).append("&")
					.append(ApplicationConstant.STATE).append("=").append(state);

			// E) Prepare request for TOKEN API
			URL url = new URL(userInputURL);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod(method);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setRequestProperty(ApplicationConstant.CONTENT_TYPE, "application/x-www-form-urlencoded");
			conn.setRequestProperty(ApplicationConstant.CACHE_CONTROL, cacheCtl);
			if (!env.equalsIgnoreCase(ApplicationConstant.SANDBOX) && authHeader != null) {
				conn.setRequestProperty(ApplicationConstant.AUTHORIZATION, authHeader);
			}
			conn.getOutputStream().write(params.toString().getBytes(StandardCharsets.UTF_8));
			conn.connect();
			int respCode = conn.getResponseCode();
			String respMsg = conn.getResponseMessage();
			if (respCode != 200) {
				throw new IOException("Response Code: " + respCode + "| Response Message: " + respMsg);
			}

			String line = "";

			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}
			reader.close();

		} catch (Exception e) {
			throw new MyInfoException();
		}
		return result.toString();
	}

	/**
	 * <p>
	 * Get Person Data
	 * </p>
	 * <p>
	 * This method calls the Person API and returns a JSON response with the
	 * personal data that was requested. Your application needs to provide a
	 * valid "access token" in exchange for the JSON data. Once your application
	 * receives this JSON data, you can use this data to populate the online
	 * form on your application.
	 * </p>
	 * 
	 * @param uinFin
	 *            the uinfin no
	 * @param bearer
	 *            the bearer token
	 * @param txnNo
	 *            the transaction no
	 * @param apiURL
	 *            the url api
	 * @param clientAppId
	 *            the client's app id
	 * @param attributes
	 *            the list of requested attributes
	 * @param env
	 *            the the environment
	 * @param myinfoPrivateKey
	 *            the private key
	 * @param proxyPersonURL
	 *            the user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the person data in json
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/oauth"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getPersonData(String uinFin, String bearer, String txnNo, String apiURL, String clientAppId,
			String attributes, String env, Key myinfoPrivateKey, String proxyPersonURL, String useProxy, String spEsvcId)
			throws MyInfoException {

		StringBuilder result = new StringBuilder();

		try {

			String userInputURL = (useProxy == ApplicationConstant.YES) ? proxyPersonURL : apiURL;
			userInputURL = userInputURL + "/" + uinFin + "/";

			apiURL = apiURL + "/" + uinFin + "/";

			String cacheCtl = ApplicationConstant.NO_CACHE;
			String method = ApplicationConstant.GET_METHOD;
			int nonceValue = new SecureRandom().nextInt();
			nonceValue = Math.abs(nonceValue);
			long timestamp = new Date().getTime();

			String signature = null;
			String authHeader = null;

			// A) Forming the Signature Base String
			TreeMap<String, String> baseParams = new TreeMap<>();
			baseParams.put(ApplicationConstant.APP_ID + "=", clientAppId);
			baseParams.put(ApplicationConstant.ATTRIBUTE + "=", attributes);
			baseParams.put(ApplicationConstant.CLIENT_ID + "=", clientAppId);
			baseParams.put(ApplicationConstant.NONCE + "=", Integer.toString(nonceValue));
			baseParams.put(ApplicationConstant.SIGNATURE_METHOD + "=", ApplicationConstant.RS256);
			baseParams.put(ApplicationConstant.SP_ESVCID + "=", spEsvcId);
			baseParams.put(ApplicationConstant.TIMESTAMP + "=", Long.toString(timestamp));
			if (txnNo != null) {
				baseParams.put(ApplicationConstant.TRANSACTION_NO + "=", txnNo);
			}
			String baseString = MyInfoSecurityHelper.generateBaseString(ApplicationConstant.GET_METHOD, apiURL,
					baseParams);

			// B) Signing Base String to get Digital Signature
			if (baseString != null) {
				signature = MyInfoSecurityHelper.generateSignature(baseString, myinfoPrivateKey);
			}

			// C) Assembling the Header
			if (signature != null) {
				TreeMap<String, String> authHeaderParams = new TreeMap<>();
				authHeaderParams.put(ApplicationConstant.TIMESTAMP + "=", Long.toString(timestamp));
				authHeaderParams.put(ApplicationConstant.NONCE + "=", Integer.toString(nonceValue));
				authHeaderParams.put(ApplicationConstant.APP_ID + "=", clientAppId);
				authHeaderParams.put(ApplicationConstant.SIGNATURE_METHOD + "=", ApplicationConstant.RS256);
				authHeaderParams.put(ApplicationConstant.SIGNATURE + "=", signature);

				String personAuthHeaderParams = MyInfoSecurityHelper.generateAuthorizationHeader(authHeaderParams,
						bearer);
				authHeader = personAuthHeaderParams + ","
						+ ApplicationConstant.BEARER + " " + bearer;

			}

			// D) Assembling the params
			StringBuilder params = new StringBuilder();

			params.append(ApplicationConstant.CLIENT_ID).append("=").append(clientAppId).append("&")
					.append(ApplicationConstant.SP_ESVCID).append("=").append(spEsvcId)
					.append("&").append(ApplicationConstant.ATTRIBUTE).append("=")
					.append(URLEncoder.encode(attributes, StandardCharsets.UTF_8.toString()));
			if (txnNo != null) {
				params.append("&").append(ApplicationConstant.TRANSACTION_NO).append("=").append(txnNo);
			}

			userInputURL = userInputURL + "?" + params.toString();
			URL url = new URL(userInputURL);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod(method);
			conn.setDoInput(true);
			conn.setRequestProperty("Cache-Control", cacheCtl);
			conn.setRequestProperty("Authorization", authHeader);
			conn.connect();
			int respCode = conn.getResponseCode();
			String respMsg = conn.getResponseMessage();

			if (respCode != 200) {
				throw new IOException("Response Code: " + respCode + "| Response Message: " + respMsg);
			}

			String line = "";

			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}
			reader.close();

		} catch (Exception e) {
			throw new MyInfoException();
		}
		return result.toString();
	}

	/**
	 * <p>
	 * Get Person Data
	 * </p>
	 * <p>
	 * This method calls the Person API without the transaction no and returns a
	 * JSON response with the personal data that was requested. Your application
	 * needs to provide a valid "access token" in exchange for the JSON data.
	 * Once your application receives this JSON data, you can use this data to
	 * populate the online form on your application.
	 * </p>
	 * 
	 * @param uinFin
	 *            the uinfin no
	 * @param bearer
	 *            the bearer token
	 * @param personurl
	 *            the api url
	 * @param clientAppId
	 *            the client's app id
	 * @param attributes
	 *            the list of requested attributes
	 * @param env
	 *            the the environment
	 * @param myinfoPrivateKey
	 *            the private key
	 * @param proxyPersonURL
	 *            the user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the person data in json
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/oauth"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getPersonData(String uinFin, String bearer, String personurl, String clientAppId,
			String attributes, String env, Key myinfoPrivateKey, String proxyPersonURL, String useProxy, 
			String spEsvcId) throws MyInfoException {
		return getPersonData(uinFin, bearer, null, personurl, clientAppId, attributes, env, myinfoPrivateKey,
				proxyPersonURL, useProxy, spEsvcId);
	}

}
