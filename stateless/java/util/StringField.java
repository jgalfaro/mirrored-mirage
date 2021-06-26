package util;

import java.util.ArrayList;
import java.util.List;

import exception.IncompatibleElementType;
import model.CondElementType;

public class StringField implements CondElementType {

	/** EMPTY StringField */
	public static final StringField EMPTY = new StringField("");
	
	/** ANY StringField */
	public static final StringField ANY = new StringField("#ANY#");
	
	private final String value;										// String Value
	
	/**
	 * Creates a StringField that contains this value.
	 * @param value A String value.
	 */
	public StringField(String value) {
		this.value = value;
	}
	
	/**
	 * Get the String value.
	 * @return The String value.
	 */
	public String getValue() {
		return value;
	}
	
	@Override
	public CondElementType getDefaultAny() {
		return ANY;
	}
	
	/**
	 * Get the intersection between this StringField and s.
	 * @param s StringField s.
	 * @return If s is the ANY StringField or this object is the ANY or s equals this, then this method returns this.
	 * Otherwise this method returns the EMPTY StringField.
	 */
	public StringField inter(StringField s) {
		return s == ANY || this.equals(s) ? this : this == ANY ? s : EMPTY;
	}

	@Override
	public CondElementType inter(CondElementType c) throws IncompatibleElementType {
		if(c instanceof StringField) return inter((StringField) c);
		throw new IncompatibleElementType(this, c);
	}

	@Override
	public boolean isEmpty() {
		return (this == EMPTY);
	}

	/**
	 * Get this StringField minus s.
	 * @param s	A valid StringField.
	 * @return The StringField list that represents this minus s.<br />
	 * <code>ANY - "payload1" = [ANY]</code><br />
	 * <code>ANY - ANY = []</code><br />
	 * <code>"payload1" - "payload1" = []</code><br />
	 * <code>"payload1" - "payload2" = ["payload1"]</code><br />
	 * The size list is always equal or less than 1.
	 */
	public List<StringField> minus(StringField s) {
		List<StringField> res = new ArrayList<StringField>();
		if(!this.equals(s) && ANY != s) res.add(this);
		return res;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<CondElementType> minus(CondElementType c) throws IncompatibleElementType {
		if(c instanceof StringField) return (List) minus((StringField) c);
		throw new IncompatibleElementType(this, c);
	}

	@Override
	public String toString() {
		return this == ANY ? "#ANY#" : this == EMPTY ? "#EMPTY#" : value;
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof StringField) {
			StringField s = (StringField) obj;
			if((s == EMPTY && this != EMPTY)
					|| (s != EMPTY && this == EMPTY)) return false;
			if((s == ANY && this != ANY)
					|| (s != ANY && this == ANY)) return false;
			else return s.value.equals(value);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return value.hashCode();
	}
	
}
