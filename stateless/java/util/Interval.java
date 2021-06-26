package util;

import java.util.LinkedList;
import java.util.List;

import model.CondElementType;

import exception.IncompatibleElementType;
import exception.IntervalException;

public class Interval implements CondElementType {

	private final int begin;			// Begin boundary interval
	private final int end;				// End boundary interval

	/** The EMPTY Interval */
	public static final Interval EMPTY = new Interval();
	
	/**
	 * Creates an Interval with a single value [value;value].
	 * @param value The single value of the Interval.
	 * @throws IntervalException Exception is thrown if value is not a positive value.
	 */
	public Interval(int value) throws IntervalException {
		this(value, value);
	}
	
	/**
	 * Creates an Interval [begin;end].
	 * @param begin	Begin boundary.
	 * @param end	End boundary.
	 * @throws IntervalException Exception is thrown. 
	 * if [begin;end] is not a valid Interval or either begin or end is not a positive value. 
	 */
	public Interval(int begin, int end) throws IntervalException {
		if(begin > end || begin < 0) throw new IntervalException(begin, end);
		this.begin = begin;
		this.end = end;
	}
	
	/**
	 * Private default constructor, only used for the EMPTY interval.
	 */
	private Interval() {
		this.begin = -1;
		this.end = -1;
	}
	
	/**
	 * Get the begin boundary of this interval [begin;end]
	 * @return the begin boundary.
	 */
	public int getBegin() {
		return begin;
	}
	
	/**
	 * Get the end boundary of this interval [begin;end]
	 * @return the begin boundary.
	 */
	public int getEnd() {
		return end;
	}
	
	public boolean isEmpty() {
		return this == EMPTY;
	}
	
	/**
	 * Indicates if this interval is a singleton, (begin == end) and this interval is [v;v].
	 * @return true if this interval contains only one value v where this interval is [v;v].
	 */
	public boolean isSingleton() {
		return !isEmpty() && begin == end;
	}

	/**
	 * Indicates if this interval contains the value v.
	 * @param v It is a positive value.
	 * @return true if this Interval contains this value. If v is not a positive value, this method will return false.
	 */
	public boolean contains(int v) {
		return v >= 0 && v >= begin && v <= end;
	}
	
	/**
	 * Get the Interval that represents the intersection between this Interval and c.
	 * @param b It is valid Interval.
	 * @return The Interval that represents the intersection between this Interval and c.
	 */
	public Interval inter(Interval b) {
		if(this.isEmpty() || b.isEmpty()) return EMPTY;
		Interval result = EMPTY;
		try {
			result = new Interval(Math.max(begin, b.begin), Math.min(end, b.end));
		} catch (IntervalException e) {}
		return result;
	}
	
	/**
	 * Get the list of Interval that represents this Interval minus b.
	 * @param b It is valid Interval.
	 * @return The list of Interval that represents this Interval minus b.
	 * If the Interval b contains this Interval, then the list is empty.<br />
	 * <code>[5;10] - [4;11] = []</code><br />
	 * <code>[5;10] - [4;7] = [[8;10]]</code><br />
	 * <code>[5;10] - [7;8] = [[5;6][9;10]]</code><br />
	 * The list size is always equal or less than 2. 
	 */
	public List<Interval> minus(Interval b) {
		List<Interval> result = new LinkedList<Interval>();
		if(inter(b).equals(EMPTY)) {
			if(!isEmpty()) result.add(this);
		}
		else {
			try {
				Interval i1 = new Interval(begin, b.begin - 1);
				result.add(i1);
			} catch (IntervalException e) {}
			try {
				Interval i2 = new Interval(b.end + 1, end);
				result.add(i2);
			} catch (IntervalException e) {}
		}
		return result;
	}
	
	@Override
	public CondElementType inter(CondElementType c) throws IncompatibleElementType {
		if(c instanceof Interval) return inter((Interval) c);
		throw new IncompatibleElementType(this, c);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<CondElementType> minus(CondElementType c) throws IncompatibleElementType {
		if(c instanceof Interval) return (List) minus((Interval) c);
		throw new IncompatibleElementType(this, c);
	}
	
	@Override
	public CondElementType getDefaultAny() {
		try {
			return new Interval(Integer.MAX_VALUE);
		} catch (IntervalException e) {}
		return null;
	}
	
	@Override
	public String toString() {
		return this == EMPTY ? "[]" : "["+begin+";"+end+"]";
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof Interval) {
			Interval i = (Interval) obj;
			return (i.begin == begin && i.end == end);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		int result = 3;
	    final int multiplier = 13;
	    result = multiplier*result + begin;
	    result = multiplier*result + end;
	    return result;
	}
	
}
