package exception;

import util.IPv4Interval;

public class NetworkIntervalException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public NetworkIntervalException(IPv4Interval interval) {
		super("It is not a network interval : " + interval);
	}
	
}
