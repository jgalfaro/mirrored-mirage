package exception;

import java.util.Set;

import util.IPv4Interval;

public class IPAddressAlreadyUsedException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public IPAddressAlreadyUsedException(IPv4Interval ipaddress, Set<IPv4Interval> network) {
		super("The IPadress " + ipaddress + " is already used in the zone " + network);
	}

}
