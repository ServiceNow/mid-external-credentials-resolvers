package com.snc.discovery;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.service_now.mid.services.Config;

/**
 * Custom External Credential Resolver for HashiCorp credential vault.
 * Uses apache http client to connect to Thycotic REST APIs and fetches secrets. 
 */
public class ThycoticCredentialResolver {

	// These are the permissible names of arguments passed INTO the resolve()
	// method.

	// the string identifier as configured on the ServiceNow instance...
	public static final String ARG_ID = "id";

	// a dotted-form string IPv4 address (like "10.22.231.12") of the target
	// system...
	public static final String ARG_IP = "ip";

	// the string type (ssh, snmp, etc.) of credential as configured on the
	// instance...
	public static final String ARG_TYPE = "type";

	// the string MID server making the request, as configured on the
	// instance...
	public static final String ARG_MID = "mid";

	// These are the permissible names of values returned FROM the resolve()
	// method.

	// the string user name for the credential, if needed...
	public static final String VAL_USER = "user";

	// the string password for the credential, if needed...
	public static final String VAL_PSWD = "pswd";

	// the string pass phrase for the credential if needed:
	public static final String VAL_PASSPHRASE = "passphrase";

	// the string private key for the credential, if needed...
	public static final String VAL_PKEY = "pkey";
	
	
	public static final String THYCOTIC_URL_PROPERTY = "mid.ext.cred.thycotic.url";
	public static final String THYCOTIC_USERNAME_PROPERTY = "mid.ext.cred.thycotic.username";
	public static final String THYCOTIC_PASSWORD_PROPERTY = "mid.ext.cred.thycotic.password";
	
	//These can be retrieved from parameters provided in config.xml file under MID agent folder 
	// or provide hard-coded values here itself.
	private String thycotic_url = "";
	private String thycotic_username = "";
	private String thycotic_password = "";

	public ThycoticCredentialResolver() {
		loadProps();
	}

	//Method to load properties from config,xml
	private void loadProps() {
		//Load parameters from MID config.xml.
		thycotic_url = Config.get().getProperty(THYCOTIC_URL_PROPERTY);
		if(isNullOrEmpty(thycotic_url))
			throw new RuntimeException("[Vault] INFO - ThycoticCredentialResolver " + THYCOTIC_URL_PROPERTY + " not set!");

		thycotic_username = Config.get().getProperty(THYCOTIC_USERNAME_PROPERTY);
		if(isNullOrEmpty(thycotic_username))
			throw new RuntimeException("[Vault] INFO - ThycoticCredentialResolver " + THYCOTIC_USERNAME_PROPERTY + " not set!");

		thycotic_password = Config.get().getProperty(THYCOTIC_PASSWORD_PROPERTY);
		if(isNullOrEmpty(thycotic_password))
			throw new RuntimeException("[Vault] INFO - ThycoticCredentialResolver " + THYCOTIC_PASSWORD_PROPERTY + " not set!");
	}

	/**
	 * Resolve a credential.
	 */
	public Map<String, String> resolve(Map<String, String> args) {
		//this can be changed if you want to use different searchField to search secrets like IP Address.
		String lookupType = "name";  // default is "name"
				
		String credentialId = (String) args.get(ARG_ID);
		String type = (String) args.get(ARG_TYPE);
		//String targetIP = (String) args.get(ARG_IP);

		String username = "";
		String password = "";
		String passphrase = "";
		String private_key = "";

		if(credentialId == null || type == null)
			throw new RuntimeException("Invalid credential Id or type found.");

		// Connect to vault and retrieve credential
		try {
			JsonObject returnedSecret = ThycoticVaultService.getSecret(lookupType, credentialId, thycotic_url, thycotic_username, thycotic_password);
			switch(type) {
				// for below listed credential type , just retrieve user name and password 
				case "windows":
				case "ssh_password": // Type SSH
				case "vmware":
				case "jdbc":
				case "jms": 
				case "basic":
					if (returnedSecret != null) {
						JsonArray array = returnedSecret.get("items").getAsJsonArray();
						for (JsonElement object : array) {
							JsonObject obj = object.getAsJsonObject();
							String fieldName = obj.get("fieldName").getAsString();
							
							//Use field name that is used for username in Secret Template
							if (fieldName.toLowerCase().equals("username")) {
								username = obj.get("itemValue").getAsString();
							} 
							
							//Use field name that is used for username in Secret Template
							if (fieldName.toLowerCase().equals("password")) {
								password = obj.get("itemValue").getAsString();
							}
						}
					}
					if(isNullOrEmpty(password)) {
						System.err.println("[Vault] ERROR - password not set!");
					}
					break;
				case "ssh_private_key": 
				case "sn_cfg_ansible": 
				case "sn_disco_certmgmt_certificate_ca":
				case "cfg_chef_credentials":
				case "infoblox": 
				case "api_key":
					//TODO: For these credential types, retrieve user name, password, ssh_passphrase, ssh_private_key from thycotic
					if (returnedSecret != null) {
						JsonArray array = returnedSecret.get("items").getAsJsonArray();
						for (JsonElement object : array) {
							JsonObject obj = object.getAsJsonObject();
							String fieldName = obj.get("fieldName").getAsString();
							
							//Use field name that is used for username in Secret Template
							if (fieldName.toLowerCase().equals("username")) {
								username = obj.get("itemValue").getAsString();
							} 
							
							//Use field name that is used for username in Secret Template
							if (fieldName.toLowerCase().equals("password")) {
								password = obj.get("itemValue").getAsString();
							}
							
							//Use field name that is used for passphrase in Secret Template
							if (fieldName.toLowerCase().equals("passphrase")) {
								passphrase = obj.get("itemValue").getAsString();
							} 
							
							//Use field name that is used for private_key in Secret Template
							if (fieldName.toLowerCase().equals("private_key")) {
								private_key = obj.get("itemValue").getAsString();
							}
						}
					}
					if(isNullOrEmpty(password)) {
						System.err.println("[Vault] ERROR - password not set!");
					}
					break;
				case "aws": ; // access_key, secret_key 	// AWS Support
					//TODO: Add code to get access_key and secret_key from thycotic with custom template
					if (returnedSecret != null) {
						JsonArray array = returnedSecret.get("items").getAsJsonArray();
						for (JsonElement object : array) {
							JsonObject obj = object.getAsJsonObject();
							String fieldName = obj.get("fieldName").getAsString();
							
							//Use field name that is used for access_key in Secret Template
							if (fieldName.toLowerCase().equals("access_key")) {
								username = obj.get("itemValue").getAsString();
							} 
							
							//Use field name that is used for username in Secret Template
							if (fieldName.toLowerCase().equals("secret_key")) {
								password = obj.get("itemValue").getAsString();
							}
						}
					}
					if(isNullOrEmpty(password)) {
						System.err.println("[Vault] ERROR - password not set!");
					}
					break;
				case "ibm": ; // softlayer_user, softlayer_key, bluemix_key
				case "azure": ; // tenant_id, client_id, auth_method, secret_key
				case "gcp": ; // email , secret_key
				default:
					System.err.println("[Vault] INFO - ThycoticCredentialResolver, not implemented credential type!");
					break;
			}
		} catch (Exception e) {
			// Catch block
			System.err.println("### Unable to connect to Vault #### ");
			e.printStackTrace();
		}
		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<String, String>();
		result.put(VAL_USER, username);
		result.put(VAL_PSWD, password);
		result.put(VAL_PKEY, private_key);
		result.put(VAL_PASSPHRASE, passphrase);
		return result;
	}

	public static boolean isNullOrEmpty(String str) {
		if(str != null && !str.isEmpty())
			return false;
		return true;
	}
	
	/**
	 * Return the API version supported by this class.
	 */
	public String getVersion() {
		return "1.0";
	}

	// main method to test Thycotic server APIs.
	// TODO: Remove this before moving to production
	public static void main(String[] args) throws Exception  {
		try {
			ThycoticCredentialResolver credResolver = new ThycoticCredentialResolver();
			// credResolver.loadProps();
			credResolver.thycotic_url = "https://thycotic.server.com/SecretServer";
			credResolver.thycotic_username = "thycotic_user";
			credResolver.thycotic_password = "thycotic_password";
			
			Map<String, String> map = new HashMap<>();
			map.put(ARG_ID, "testcredid");
			map.put(ARG_TYPE, "windows");
			
			Map<String, String> result = credResolver.resolve(map);
			
			System.out.println("Found Secret Details : " + result);
		} finally {
			
		}
	}
}