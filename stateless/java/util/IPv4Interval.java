package util;

import java.util.LinkedList;
import java.util.List;

import model.CondElementType;

import exception.IPv4IntervalException;
import exception.IncompatibleElementType;
import exception.IntervalException;

public class IPv4Interval implements CondElementType {

	/** Byte Interval is [0;255]*/
	public final static Interval BYTE = getByteInterval();

	/** EMPTY IPv4Interval [].[].[].[] */
	public static final IPv4Interval EMPTY = new IPv4Interval();
	
	// IPv4Interval is A.B.C.D
	private final Interval A;
	private final Interval B;
	private final Interval C;
	private final Interval D;
	
	/**
	 * Creates an IPv4Interval that contains a single IPv4 : A.B.C.D
	 * @param A Integer A.
	 * @param B Integer B.
	 * @param C Integer C.
	 * @param D Integer D.
	 * @throws IntervalException Exception is thrown if it is not a valid IPv4Interval.
	 */
	public IPv4Interval(int A, int B, int C, int D) throws IntervalException {
		this(new Interval(A), new Interval(B), new Interval(C), new Interval(D));
	}
	
	/**
	 * Creates an IPv4Interval A.B.C.[d1;d2]
	 * @param A Integer A.
	 * @param B Integer B.
	 * @param C Integer C.
	 * @param D Interval D.
	 * @throws IntervalException Exception is thrown if it is not a valid IPv4Interval.
	 */
	public IPv4Interval(int A, int B, int C, Interval D) throws IntervalException {
		this(new Interval(A), new Interval(B), new Interval(C), D);
	}
	
	/**
	 * Creates an IPv4Interval A.B.[c1;c2].[0;255]
	 * @param A Integer A.
	 * @param B Integer B.
	 * @param C Interval C.
	 * @param D Interval D.
	 * @throws IntervalException Exception is thrown if it is not a valid IPv4Interval.
	 */
	public IPv4Interval(int A, int B, Interval C, Interval D) throws IntervalException {
		this(new Interval(A), new Interval(B), C, D);
	}
	
	/**
	 * Creates an IPv4Interval A.[b1;b2].[0;255].[0;255]
	 * @param A Integer A.
	 * @param B Interval B.
	 * @param C Interval C.
	 * @param D Interval D.
	 * @throws IntervalException Exception is thrown if it is not a valid IPv4Interval.
	 */
	public IPv4Interval(int A, Interval B, Interval C, Interval D) throws IntervalException {
		this(new Interval(A), B, C, D);
	}
	
	/**
	 * Creates an IPv4Interval [a1;a2].[0;255].[0;255].[0;255]
	 * @param A Interval A.
	 * @param B Interval B.
	 * @param C Interval C.
	 * @param D Interval D.
	 * @throws IntervalException Exception is thrown if it is not a valid IPv4Interval.
	 */
	public IPv4Interval(Interval A, Interval B, Interval C, Interval D) throws IPv4IntervalException {
		if(A.isEmpty() || B.isEmpty() || C.isEmpty() || D.isEmpty()
			|| !BYTE.inter(A).equals(A)
			|| !BYTE.inter(B).equals(B)
			|| !BYTE.inter(C).equals(C)
			|| !BYTE.inter(D).equals(D)
			) throw new IPv4IntervalException(A, B, C, D);
		this.A = A;
		this.B = this.A.isSingleton() ? B : BYTE;
		this.C = this.B.isSingleton() ? C : BYTE;
		this.D = this.C.isSingleton() ? D : BYTE;
	}
	
	/**
	 * Private constructor than creates the EMPTY IPv4Interval.
	 */
	private IPv4Interval() {
		A = Interval.EMPTY;
		B = Interval.EMPTY;
		C = Interval.EMPTY;
		D = Interval.EMPTY;
	}
	
	/**
	 * Get the BYTE Interval [0,255].
	 * @return Interval [0;255].
	 */
	private static Interval getByteInterval() {
		try {
			return new Interval(0, 255);
		} catch (IntervalException e) {
			return null;
		}
	}
	
	/**
	 * IPv4Interval is A.B.C.D where A, B, C and D are Interval objects.
	 * @return The Interval A.
	 */
	public Interval getA() {
		return A;
	}

	/**
	 * IPv4Interval is A.B.C.D where A, B, C and D are Interval objects.
	 * @return The Interval B.
	 */
	public Interval getB() {
		return B;
	}

	/**
	 * IPv4Interval is A.B.C.D where A, B, C and D are Interval objects.
	 * @return The Interval C.
	 */
	public Interval getC() {
		return C;
	}

	/**
	 * IPv4Interval is A.B.C.D where A, B, C and D are Interval objects.
	 * @return The Interval D.
	 */
	public Interval getD() {
		return D;
	}
	
	public boolean isEmpty() {
		return this == EMPTY;
	}
	
	/**
	 * Indicates if this IPv4Interval is a singleton A.B.C.D where A, B, C and D are singleton Interval.
	 * @return true if IPv4Interval is a singleton.
	 */
	public boolean isSingleton() {
		return this != EMPTY && A.isSingleton() && B.isSingleton() && C.isSingleton() && D.isSingleton();
	}
	
	/**
	 * Indicates if this IPv4Interval contains the IPv4Interval i.
	 * @param i A valid IPv4Interval.
	 * @return true if this IPv4Interval contains i.<br />
	 * <code>192.168.[120;121].[0;255] contains 192.168.120.[100;200] = true</code>
	 */
	public boolean contains(IPv4Interval i) {
		return (this != EMPTY && i != EMPTY && i != null)
			&& i.minus(this).size() == 0;
	}
	
	/**
	 * Get the IPv4Interval intersection between this IPv4Interval and i. 
	 * @param i A valid IPv4Interval.
	 * @return The IPv4Interval intersection between this IPv4Interval and i.<br />
	 * <code>192.168.[120;121].[0;255] inter 192.168.[115;120].[0;255] = 192.168.120.[0;255]</code>
	 */
	public IPv4Interval inter(IPv4Interval i) {
		IPv4Interval result;
		if(i == null) return this;
		Interval a = A.inter(i.A);
		Interval b = a.isSingleton() ? B.inter(i.B) : BYTE;
		Interval c = b.isSingleton() ? C.inter(i.C) : BYTE;
		Interval d = c.isSingleton() ? D.inter(i.D) : BYTE;
		try {
			result = new IPv4Interval(a, b, c, d);
		} catch (IPv4IntervalException e) {result = EMPTY;}
		return result;
	}
	
	/**
	 * Get this IPv4Interval minus i.
	 * @param i A valid IPv4Interval.
	 * @return The list of IPv4Interval that represents this minus i.<br />
	 * <code>[190;200].[0;255].[0;255].[0;255] minus 192.[168;180].[0;255].[0;255]<br />
	 * =<br />
	 * [[190;191].[0.255].[0.255].[0.255],<br />
	 *  [193;200].[0.255].[0.255].[0.255],<br />
	 *  192.[0.167].[0.255].[0.255],<br />
	 *  192.[191;255].[0.255].[0.255]]<br />
	 * </code>
	 */
	public List<IPv4Interval> minus(IPv4Interval i) {
		List<IPv4Interval> result = new LinkedList<IPv4Interval>();
		if(i == EMPTY) result.add(this);
		else {
			List<Interval> list = A.minus(i.A);
			addIPv4Intervals(result, list, A, A, B, C, D);
			Interval a1 = A.inter(i.A);
			list = B.minus(i.B);
			addIPv4Intervals(result, list, B, a1, B, C, D);
			Interval b1 = B.inter(i.B);
			list = C.minus(i.C);
			addIPv4Intervals(result, list, C, a1, b1, C, D);
			Interval c1 = C.inter(i.C);
			list = D.minus(i.D);
			addIPv4Intervals(result, list, D, a1, b1, c1, D);
		}
		return result;
	}
	
	@Override
	public CondElementType inter(CondElementType c) throws IncompatibleElementType {
		if(c instanceof IPv4Interval) return inter((IPv4Interval) c);
		throw new IncompatibleElementType(this, c);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<CondElementType> minus(CondElementType c) throws IncompatibleElementType {
		if(c instanceof IPv4Interval) return (List) minus((IPv4Interval) c);
		throw new IncompatibleElementType(this, c);
	}
	
	@Override
	public CondElementType getDefaultAny() {
		try {
			return new IPv4Interval(BYTE, BYTE, BYTE, BYTE);
		} catch (IntervalException e) {}
		return null;
	}
	
	/**
	 * addIPv4Interval in the result for the minus method.
	 * @param result The minus result.
	 * @param list Interval list.
	 * @param pos This value is A, B, C or D.
	 * @param A Interval A.
	 * @param B Interval B.
	 * @param C Interval C.
	 * @param D Interval D.
	 */
	private void addIPv4Intervals(List<IPv4Interval> result, List<Interval> list, Interval pos, Interval A, Interval B, Interval C, Interval D) {
		if(A.isEmpty() || B.isEmpty() || C.isEmpty() || D.isEmpty()) return;
		// Add new IPv4Interval for each Interval of the list.
		for(Interval in : list) {
			try {
				IPv4Interval i = (pos == A) ? new IPv4Interval(in, B, C, D)
									: (pos == B) ? new IPv4Interval(A, in, C, D)
									: (pos == C) ? new IPv4Interval(A, B, in, D)
									: new IPv4Interval(A, B, C, in);
				result.add(i);
			} catch (IPv4IntervalException e) {}
		}
	}
	
	@Override
	public String toString() {
		return A + "." + B + "." + C + "." + D;
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof IPv4Interval) {
			IPv4Interval i = (IPv4Interval) obj;
			return A.equals(i.A) && B.equals(i.B) && C.equals(i.C) && D.equals(i.D);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		if(isSingleton()) return new Integer(A.getBegin() * 16777216 + B.getBegin() * 65536 + C.getBegin() * 256 + D.getBegin());
		else {
			int result = 7;
	    	final int multiplier = 17;
	    	result = multiplier*result + A.getBegin();
	    	result = multiplier*result + A.getEnd();
	    	result = multiplier*result + B.getBegin();
	    	result = multiplier*result + B.getEnd();
	    	result = multiplier*result + C.getBegin();
	    	result = multiplier*result + C.getEnd();
	    	result = multiplier*result + D.getBegin();
	    	result = multiplier*result + D.getEnd();
	    	return result;
		}
	}
	
}
