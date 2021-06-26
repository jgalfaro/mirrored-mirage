package exception;

import util.Interval;

public class IPv4IntervalException extends IntervalException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public IPv4IntervalException(String msg) {
		super(msg);
	}
	
	public IPv4IntervalException(Interval A, Interval B, Interval C, Interval D) {
		super(A + "." + B + "." + C + "." + D + " is not a valid IP interval");
	}
		
}
