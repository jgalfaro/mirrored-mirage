package exception;

public class IntervalException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public IntervalException(String msg) {
		super(msg);
	}
	
	public IntervalException(int begin, int end) {
		super("[" + begin + ";" + end + "] is not a valid interval");
	}
		
}
