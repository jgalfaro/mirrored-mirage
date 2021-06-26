package exception;

import model.CondElementType;

public class IncompatibleElementType extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public IncompatibleElementType(CondElementType c1, CondElementType c2) {
		super("Incompatible types : " + c1.getClass().getName() + " " + c2.getClass().getName());
	}
	
}
