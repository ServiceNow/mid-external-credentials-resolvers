# MID Server External Credential Resolver for Thycotic Secret Server

This is the ServiceNow MID Server custom external credential resolver for the Thycotic Secret Server credential storage.

# Pre-requisites:

Thycotic External Credential Resolver requires JDK 1.8 or newer
Eclipse or any equivalent IDE

# Steps to build
* Clone this repository.
* Import the project in Eclipse or any IDE.
* Update MID Server agent path in pom.xml to point to valid MID Server location.
* Update the code in ThycoticCredentialResolver.java to customize anything.
* Use below maven command or IDE (Eclipse or Intellij) maven build option to build the jar.

	> mvn clean package

* thycotic-external-credentials-0.0.1-SNAPSHOT.jar will be generated under target folder.

# Steps to install and use Thycotic Secret Server as external credential resolver

* Make sure that “External Credential Storage” plugin (com.snc.discovery.external_credentials) is installed in your ServiceNow instance.
* Import the thycotic-external-credentials-0.0.1-SNAPSHOT.jar file from target folder in ServiceNow instance.
	- Navigate to MID Server – JAR Files
	- Create a New Record by clicking New
	- Name it “ThycoticCredentialResolver”, version 0.0.1 and attach thycotic-external-credentials-0.0.1-SNAPSHOT.jar from target folder.
	- Click Submit
* Create Credential in the instance with "External credential store" flag activated.
* Update the config.xml in MID Server with below parameters and restart the MID Server.

   <parameter name="ext.cred.thycotic.url" value="<Thycotic Secret Server URL>"/> 
   <parameter name="ext.cred.thycotic.username" value="<Thycotic login username>"/>
   <parameter name="ext.cred.thycotic.password" secure="true" value="<Thycotic login password>"/>

* Ensure that the "Credential ID" match a Secret Name in your Thycotic Secret Server (ex: mysecretname)
* Ensure that the Secret in the secret server contain keys matching the ServiceNow credential record fields (ex: username, password)



