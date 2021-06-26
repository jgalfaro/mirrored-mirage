package exception;

public class TopologyWriterException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public TopologyWriterException(Throwable t) {
		super(t);
	}
	
	public TopologyWriterException(String m) {
		super(m);
	}

}
