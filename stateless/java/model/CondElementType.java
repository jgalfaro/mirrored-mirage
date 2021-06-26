package model;

import java.util.List;

import exception.IncompatibleElementType;

public interface CondElementType {

	/**
	 * The list of CondElementType that represents this object condition minus c.
	 * @param c CondElementType c.
	 * @return The list of CondElementType that represents this object condition minus c.
	 * @throws IncompatibleElementType Exception is thrown if this object incompatible with c.
	 */
	public List<CondElementType> minus(CondElementType c) throws IncompatibleElementType;
		
	/**
	 * Get a CondElementType that represents the intersection between this object and c.
	 * @param c CondElementType c.
	 * @return A CondElementType that represents the intersection between this object and c.
	 * @throws IncompatibleElementType Exception is thrown if this object incompatible with c.
	 */
	public CondElementType inter(CondElementType c) throws IncompatibleElementType;

	/**
	 * Get the default ANY element.
	 * @return The default ANY element.
	 */
	public CondElementType getDefaultAny();
	
	/**
	 * Indicates if this element is the EMPTY element.
	 * @return true if this element is the EMPTY element.
	 */
	public boolean isEmpty();
	
}
