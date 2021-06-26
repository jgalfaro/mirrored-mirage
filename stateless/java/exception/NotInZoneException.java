package exception;

import java.util.Set;

import util.IPv4Interval;

public class NotInZoneException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public NotInZoneException(IPv4Interval ipadress, Set<IPv4Interval> network) {
		super("The ipadress " + ipadress + " is not in the zone " + network);
	}
	
	public NotInZoneException(IPv4Interval ipadress) {
		super("Received a zone instead of a ipadress : " + ipadress);
	}

	
}
