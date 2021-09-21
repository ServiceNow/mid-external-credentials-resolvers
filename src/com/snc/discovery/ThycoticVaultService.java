package com.snc.discovery;


import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * 
 * Service class to call Thycotic Secret Server REST APIs.
 *
 */
public class ThycoticVaultService {

	public static CloseableHttpClient getHttpClient() {
		try {
			SSLContextBuilder builder = new SSLContextBuilder();
			builder.loadTrustMaterial(null, new TrustStrategy() {
				@Override
				public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					return true;
				}
			});
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), new NoopHostnameVerifier());
			return HttpClients.custom().setSSLSocketFactory(sslsf).build();
		} catch (Exception e) {
			return HttpClients.createDefault();
		}
	}

	public static JsonObject getSecret(String lookupField, String secretName, String thycoticUrl, String username, String password) throws Exception {
		CloseableHttpClient httpclient = getHttpClient();
		try {
			String token = authenticate(httpclient, thycoticUrl, username, password);
			
			String secretId = searchSecrets(httpclient, thycoticUrl, token, lookupField, secretName);
			return getSecret(httpclient, thycoticUrl, token, secretId);
		} finally {
			httpclient.close();
		}
	}



	public static String authenticate(CloseableHttpClient httpclient, String secretServerUrl, String username, String password) throws Exception {
		HttpPost httpPost = new HttpPost(secretServerUrl+"/oauth2/token");
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("username", username));
		nvps.add(new BasicNameValuePair("password", password));
		nvps.add(new BasicNameValuePair("grant_type", "password"));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));

		CloseableHttpResponse response2 = httpclient.execute(httpPost);

		try {
			String json = EntityUtils.toString(response2.getEntity(), "UTF-8");
			String token = "";
			
			JsonParser parser = new JsonParser();
			JsonObject resultObject = parser.parse(json).getAsJsonObject();

				if (resultObject.get("error") != null) {
					throw new Exception("Error authenticating. Ensure username / password are correct and web services are enabled");
				}
				token = resultObject.get("access_token").getAsString();
			return token;
		} finally {
			response2.close();
		}
	}

	public static String searchSecrets(CloseableHttpClient httpclient, String secretServerUrl, String token, String searchField, String searchText) throws Exception {

		//Specify the Secret Template ID and Folder ID to create the Secret In
		String filter = secretServerUrl+"/api/v1/secrets?filter.includeRestricted=false&filter.searchField=%s&filter.searchtext=%s";
		String formattedFilter = String.format(filter, searchField, searchText);

		JsonObject secretResult = getObject(httpclient, formattedFilter, token);
		JsonArray secrets = secretResult.get("records").getAsJsonArray();
		for (JsonElement secret : secrets) {
			JsonObject jsonSecret = secret.getAsJsonObject();
			if (searchText.equals(jsonSecret.get(searchField).getAsString())) {
				return String.valueOf(jsonSecret.get("id").getAsLong());
			} else {
				throw new Exception ("No secret found for the given secret: " + searchText);
			}
		}
		return null;
	}

	public static JsonObject getSecret(CloseableHttpClient httpclient, String secretServerUrl, String token, String secretId) throws Exception {
		secretServerUrl = secretServerUrl+"/api/v1/secrets/"+secretId;
		JsonObject returnedSecret = getObject(httpclient, secretServerUrl, token);
		return returnedSecret;
	}

	public static String getSecretField(CloseableHttpClient httpclient, String secretServerUrl, String token, Integer secretId, String secretFieldName) throws Exception {
		secretServerUrl = secretServerUrl+"/api/v1/secrets/"+secretId+"/fields/"+secretFieldName;
		String returnedFieldValue = getValue(httpclient, secretServerUrl, token);

		return returnedFieldValue;
	}


	private static JsonObject getObject(CloseableHttpClient httpclient, String secretServerUrl, String token) throws Exception {

		HttpGet httpGet = new HttpGet(secretServerUrl);		
		//Add bearer token to header
		httpGet.setHeader("Authorization", "Bearer " + token);
		CloseableHttpResponse response2 = httpclient.execute(httpGet);	
		try {
			//Get status of call
			String json = EntityUtils.toString(response2.getEntity(), "UTF-8");	   
			JsonParser parser = new JsonParser();
			JsonObject resultObject = parser.parse(json).getAsJsonObject();
			if (resultObject.get("message") != null) {
				throw new Exception ("Error getting object: " + resultObject.get("message"));
			}
			return resultObject;
		} finally {
			response2.close();
		}	
	}

	private static String getValue(CloseableHttpClient httpclient, String secretServerUrl, String token) throws Exception {

		HttpGet httpGet = new HttpGet(secretServerUrl);		
		//Add bearer token to header
		httpGet.setHeader("Authorization", "Bearer " + token);
		CloseableHttpResponse response2 = httpclient.execute(httpGet);	
		try {
			//Get status of call
			String json = EntityUtils.toString(response2.getEntity(), "UTF-8");	   
			return json;
		} finally {
			response2.close();
		}	
	}
}
