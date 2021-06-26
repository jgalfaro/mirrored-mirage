package util;

import model.CondElementType;
import exception.IntervalException;

public class PortInterval extends Interval {

	/** Maximum port value is 65365 */
	public static final int MAX = 65535;
	
	/**
	 * Creates a PortInterval with a single [value;value].
	 * @param value The single value of this PortInterval.
	 * @throws IntervalException Exception is thrown if value is not a positive value or if value is greater than 65535.
	 */
	public PortInterval(int value) throws IntervalException {
		super(value);
		if(value > MAX) throw new IntervalException(value, value);
	}

	/**
	 * Creates a PortInterval [begin;end].
	 * @param begin Begin boundary.
	 * @param end End boundary.
	 * @throws IntervalException Exception is thrown if [begin;value] is not a valid Interval
	 * or if begin, end are greater than 65535.
	 */
	public PortInterval(int begin, int end) throws IntervalException {
		super(begin, end);
		if(begin > MAX || end > MAX) throw new IntervalException(begin, end);
	}
	
	@Override
	public CondElementType getDefaultAny() {
		try {
			return new PortInterval(MAX);
		} catch (IntervalException e) {}
		return null;
	}
	
}
