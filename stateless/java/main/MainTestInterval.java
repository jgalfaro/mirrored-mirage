package main;

import util.IPv4Interval;
import util.Interval;
import exception.IntervalException;

public class MainTestInterval {

	public static void main(String[] args) throws Exception {
		//test1();
		//test2();
		//test3();
		//test4();
		test5();
		//testIP();
		//testIP2();
		testIP3();
		//testIPminus();
	}
	
	public static void test1() throws IntervalException {
		Interval a = new Interval(2);
		Interval b = new Interval(1,5);
		Interval c = Interval.EMPTY;
		Interval b2 = new Interval(1,5);
		Interval d = new Interval(6,7);
		Interval e = new Interval(3,5);
		System.out.println(a + " " + b + " " + c);
		System.out.println(b.equals(b2));
		System.out.println(a.inter(b));
		System.out.println(b2.inter(b));
		System.out.println(b.inter(d));
	}
	
	public static void test2() throws IntervalException {
		Interval a = new Interval(1,7);
		Interval b = new Interval(5,8);
		Interval c = new Interval(3,6);
		Interval d = new Interval(3,7);
		Interval e = new Interval(1,2);
		
		System.out.println(a.minus(b));
		System.out.println(a.minus(c));
		System.out.println(a.minus(d));
		
		System.out.println(b.minus(a));
		System.out.println(c.minus(a));
		System.out.println(d.minus(a));
		
		System.out.println(a.minus(a));
		System.out.println(d.minus(e));
		
		System.out.println(new Interval(1,5).minus(new Interval(10,20)));
	}

	public static void test3() throws IntervalException {
		Interval a = new Interval(10,40);
		Interval b = new Interval(20,30);
		Interval c = new Interval(1,50);
		Interval d = new Interval(1,50);
		
		System.out.println(a + ", " + c + ", " + b + ", " + d);
		System.out.println(c.minus(a));
		System.out.println(d.minus(b));
	}
	
	public static void test4() throws IntervalException {
		Interval BYTE = new Interval(0,255);
		Interval ALL = new Interval(0, 1234567);
		System.out.println(Interval.EMPTY);
		System.out.println(ALL.inter(BYTE));
		System.out.println(ALL.inter(BYTE).minus(new Interval(12, 45)));
	}

	public static void test5() throws IntervalException {
		Interval a = new Interval(136,160);
		Interval b = new Interval(136,179);
		System.out.println(a);
		System.out.println(b);
		System.out.println(b.minus(a));
	}
	
	public static void testIP() throws Exception {
		IPv4Interval a = new IPv4Interval(new Interval(192), new Interval(168),
						new Interval(120), new Interval(10, 50));
		IPv4Interval b = new IPv4Interval(new Interval(192, 200), new Interval(168),
				new Interval(120), new Interval(10, 50));
		IPv4Interval c = new IPv4Interval(new Interval(192, 200), IPv4Interval.BYTE,
				IPv4Interval.BYTE, IPv4Interval.BYTE);
		System.out.println(a);
		System.out.println(b);
		System.out.println(c);
		System.out.println(b.equals(c));
		
	}

	public static void testIP2() throws Exception {
		IPv4Interval a = new IPv4Interval(new Interval(192), new Interval(168),
				new Interval(120), new Interval(10, 50));
		IPv4Interval b = new IPv4Interval(new Interval(192, 200), new Interval(168),
				new Interval(120), new Interval(10, 50));
		IPv4Interval c = new IPv4Interval(new Interval(192, 200), IPv4Interval.BYTE,
				IPv4Interval.BYTE, IPv4Interval.BYTE);
		IPv4Interval d = new IPv4Interval(new Interval(192), new Interval(170, 180),
				IPv4Interval.BYTE, IPv4Interval.BYTE);
		System.out.println(a);
		System.out.println(b);
		System.out.println(c);
		System.out.println(d);
		System.out.println(" a inter b = " + a.inter(b));
		System.out.println(" a inter c = " + a.inter(c));
		System.out.println(" a inter d = " + a.inter(d));
		System.out.println(" b inter c = " + b.inter(c));
		System.out.println(" b inter d = " + b.inter(d));
		
	}
	
	public static void testIP3() throws Exception {
		IPv4Interval a = new IPv4Interval(192, 168, 130, new Interval(136, 160));
		IPv4Interval b = new IPv4Interval(192, 168, 130, new Interval(136, 179));
		System.out.println(a);
		System.out.println(b);
		System.out.println(b.minus(a));
	}
	
	public static void testIPminus() throws Exception {
		Interval BYTE = IPv4Interval.BYTE;
		IPv4Interval a = new IPv4Interval(new Interval(192, 200), BYTE, BYTE, BYTE);
		IPv4Interval b = new IPv4Interval(new Interval(193), new Interval(2, 30), BYTE, BYTE);
	
		System.out.println(a + " " + b);
		System.out.println("a minus b = " + a.minus(b));
		System.out.println("b minus a = " + b.minus(a));
	}
	
}
