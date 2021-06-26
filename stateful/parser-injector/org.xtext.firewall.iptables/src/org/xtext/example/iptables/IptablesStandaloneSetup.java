
package org.xtext.example.iptables;

/**
 * Initialization support for running Xtext languages 
 * without equinox extension registry
 */
public class IptablesStandaloneSetup extends IptablesStandaloneSetupGenerated{

	public static void doSetup() {
		new IptablesStandaloneSetup().createInjectorAndDoEMFRegistration();
	}
}

