# MyInfo Connector for Java

MyInfo Connector aims to simplify consumer's integration effort with MyInfo by providing an easy to use Java library to integrate into your application.

## Requirements

Java 1.7 and later

### 1.1 Maven Installation

Add the following to your application's pom.xml

```xml
<dependency>
	<groupId>MyInfoConnector-1.0.jar</groupId>
	<artifactId>MyInfoConnector-1.0.jar</artifactId>
	<scope>system</scope>
	<version>1.0</version>
	<systemPath>${basedir}\src\main\webapp\WEB-INF\lib\MyInfoConnector-1.0.jar</systemPath>
</dependency>
```

### 1.2 Import Connector

Import the MyInfoConnector.java into your code as below:

```java
import sg.gov.ndi.MyInfoConnector;
```

### 1.3 Properties file
You are required to create a properties file with the following properties for this library. Samples of the properties file can be found in this repository under the Sample Properties folder.
| Required Properties | Description |
| -------- | ----------- |
| KEYSTORE | Absolute path of the Java keystore that store all the private/public keys. |
| KEYSTORE_PASSPHRASE | Password of your Java keystore. |
| KEYSTORE_PRIVATE_KEY_PASSPHRASE | Password of the private key. |
| PRIVATE_KEY_ALIAS | Alias of the private key in the Java keystore. |
| PUBLIC_CERT_ALIAS | Alias of the MyInfo public certificate in the Java keystore. |
| CLIENT_ID | Unique ID provided upon approval of your application to use MyInfo. For our sample application, it is **STG2-MYINFO-SELF-TEST** |
| CLIENT_SECRET | Secret key provided upon approval of your application to use MyInfo. For our sample application, it is **44d953c796cccebcec9bdc826852857ab412fbe2** |
| REDIRECT_URL | The callback URL specified when invoking the authorise call. For our sample application, it is http://localhost:3001/callback |
| ATTRIBUTES | Comma separated list of attributes requested. Possible attributes are listed in the Person object definition in the API specifications. |
| ENVIRONMENT | The environment your application is configured. This can be **SANDBOX**, **TEST** or **PROD**. |
| TOKEN_URL | Specify the TOKEN API URL for MyInfo. The API is available in three environments:<br> SANDBOX: **https://sandbox.api.myinfo.gov.sg/com/v3/token**<br> TEST: **https://test.api.myinfo.gov.sg/com/v3/token**<br> PROD:  **https://api.myinfo.gov.sg/com/v3/token** |
| PERSON_URL | Specify the TOKEN API URL for MyInfo. The API is available in three environments:<br> SANDBOX: **https://sandbox.api.myinfo.gov.sg/com/v3/person**<br> TEST: **https://test.api.myinfo.gov.sg/com/v3/person**<br> PROD:  **https://api.myinfo.gov.sg/com/v3/person** |
| USE_PROXY | Indicate the use of proxy url. It can be either **Y** or **N**. |
| PROXY_TOKEN_URL | If you are using a proxy url, specify the proxy URL for TOKEN API here. |
| PROXY_PERSON_URL | If you are using a proxy url, specify the proxy URL for PERSON API here. |

## How to use the connector

### 1. Get a single instance of MyInfoConnector

Get a single instance of MyInfoConnector and load properties file:

```
MyInfoConnector connector = MyInfoConnector.getInstance("C:\\MyInfoConnectorPROD.properties");
```

Once the properties file are loaded, you may retrieve the instance again with the below method:
```
MyInfoConnector connector = MyInfoConnector.getCurrentInstance();
```

### 2. Retrieve person's data
Retrieve person's data by passing the authorisation code and state from the Authorise API call:

```
connector.getMyInfoPersonData(authCode,state);
```
**txnNo** is an optional parameter that can be passed through the overloaded method, if required.
```
connector.getMyInfoPersonData(authCode,txnNo,state);
```

## Helper methods

Under the hood, MyInfoConnector make use of **MyInfoSecurityHelper** and you may use the class as util methods to meet your application needs.

### 1. Forming the Signature Base String
This method takes in the API call method (GET, POST, etc.), API URL, and all the required parameters into a treemap, sort them and form the base string.
```
MyInfoSecurityHelper.generateBaseString(method, urlProp, baseParams);
```

### 2. Generating the Signature
This method takes in the base string and the private key to sign and generate the signature.
```
MyInfoSecurityHelper.generateSignature(baseString, privateKey);
```

### 3. Assembling the Header
This method takes in all the required parameters into a treemap and assemble the header.
```
MyInfoSecurityHelper.generateAuthorizationHeader(authHeaderParams);
```
It also provide an overloaded method that takes in the bearer token, if required.
```
MyInfoSecurityHelper.generateAuthorizationHeader(authHeaderParams, bearer);
```

### 4. Decrypting and retrieving the Payload
This method takes in the result from the **person** API call  and the private key to decrypt and retrieve the payload.
```
MyInfoSecurityHelper.getPayload(result, privateKey);
```

### 5. Verify Token
This method takes in the decrypted payload and the public key to verify the token.
```
MyInfoSecurityHelper.verifyToken(decryptedPayload, pubKey);
```

## Reporting issues

You may contact [support@myinfo.gov.sg](mailto:support@myinfo.gov.sg) for any other technical issues, and we will respond to you within 5 working days.
