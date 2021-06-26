package main;

import java.util.ArrayList;
import java.util.List;

import exception.IntervalException;

import util.IPv4Interval;
import util.Interval;

public class MainTestHash {

	public static void main(String[] args) throws IntervalException {
		System.out.println(Integer.MAX_VALUE);
		System.out.println("hash1");
		test0();
		System.out.println("hash2");
		test1();
	}
	
	public static void test0() throws IntervalException {
		List<Integer> l = new ArrayList<Integer>();
		for(int a = 0; a < 255; a++) {
			Interval i = new Interval(a);
			if(l.contains(i.hashCode())) System.out.println(i + " collision : " + i.hashCode());
			l.add(i.hashCode());
		}
	}
	
	public static void test1() throws IntervalException {
		List<Integer> l = new ArrayList<Integer>();
		for(int a = 0; a < 255; a++) {
			for(int b = 0; b < 255; b++) {
				for(int c = 0; c < 255; c++) {
					for(int d = 0; d < 255; d++) {
						IPv4Interval i = new IPv4Interval(a, b, c, d);
						int hash;
						try {
							hash = i.hashCode();
						} catch(NumberFormatException e) {
							System.out.println(i);
							throw e;
						}
						if(l.contains(hash)) {
							System.out.println(l);
							System.out.println(i + "collision : " + hash);
							System.exit(0);
						}
						else l.add(hash);
					}
				}
			}
		}
	}
	
}
