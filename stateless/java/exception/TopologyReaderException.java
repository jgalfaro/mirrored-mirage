package exception;

public class TopologyReaderException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public TopologyReaderException(Throwable t) {
		super(t);
	}
	
	public TopologyReaderException(String m) {
		super(m);
	}

}
