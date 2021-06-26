package tests.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static util.IPv4Interval.BYTE;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import exception.IntervalException;

public class IPv4IntervalTest {

	@Test public void testConstructor1() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,120,113);
			assertEquals(new Interval(192), i.getA());
			assertEquals(new Interval(168), i.getB());
			assertEquals(new Interval(120), i.getC());
			assertEquals(new Interval(113), i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testConstructor2() {
		try {
			new IPv4Interval(192,168,120,256);
			fail("Exception should be found");
		} catch (IntervalException e) {
			assertTrue(true);
		}
	}

	@Test public void testConstructor3() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,120,new Interval(30,70));
			assertEquals(new Interval(192), i.getA());
			assertEquals(new Interval(168), i.getB());
			assertEquals(new Interval(120), i.getC());
			assertEquals(new Interval(30,70), i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testConstructor4() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,new Interval(10, 200),BYTE);
			assertEquals(new Interval(192), i.getA());
			assertEquals(new Interval(168), i.getB());
			assertEquals(new Interval(10, 200), i.getC());
			assertEquals(BYTE, i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testConstructor5() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,new Interval(10,200),new Interval(15, 30));
			assertEquals(new Interval(192), i.getA());
			assertEquals(new Interval(168), i.getB());
			assertEquals(new Interval(10,200), i.getC());
			assertEquals(BYTE, i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstructor6() {
		try {
			IPv4Interval i = new IPv4Interval(new Interval(192,195), BYTE, BYTE, BYTE);
			assertEquals(new Interval(192,195), i.getA());
			assertEquals(BYTE, i.getB());
			assertEquals(BYTE, i.getC());
			assertEquals(BYTE, i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstructor7() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,new Interval(10,200),new Interval(15, 30));
			assertEquals(new Interval(192), i.getA());
			assertEquals(new Interval(168), i.getB());
			assertEquals(new Interval(10,200), i.getC());
			assertEquals(IPv4Interval.BYTE, i.getD());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void isSingleton1() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,new Interval(10,200),BYTE);
			assertFalse(i.isSingleton());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void isSingleton2() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,120,113);
			assertTrue(i.isSingleton());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void isSingleton3() {
		assertFalse(IPv4Interval.EMPTY.isSingleton());
	}
	
	@Test public void isEmpty1() {
		try {
			IPv4Interval i = new IPv4Interval(192,168,new Interval(10,200),BYTE);
			assertFalse(i.isEmpty());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void isEmpty2() {
		assertTrue(IPv4Interval.EMPTY.isEmpty());
	}

	@Test public void testEquals1() {
		try {
			IPv4Interval a = new IPv4Interval(192,168,new Interval(10,200),new Interval(15, 30));
			IPv4Interval b = new IPv4Interval(192,168,new Interval(10,200),new Interval(15, 30));
			assertTrue(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testEquals2() {
		try {
			IPv4Interval a = new IPv4Interval(192,168,new Interval(10,200),BYTE);
			IPv4Interval b = new IPv4Interval(192,168,new Interval(10,201),BYTE);
			assertFalse(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testContains1() {
		try {
			IPv4Interval a = new IPv4Interval(192,168,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,168,new Interval(10,201),BYTE);
			assertTrue(a.contains(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testContains2() {
		try {
			IPv4Interval a = new IPv4Interval(192,168,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,168,new Interval(10,201),BYTE);
			assertFalse(b.contains(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains3() {
		try {
			IPv4Interval a = new IPv4Interval(192,BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,new Interval(10,201),BYTE,BYTE);
			assertTrue(a.contains(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testContains4() {
		try {
			IPv4Interval a = new IPv4Interval(192,BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,new Interval(10,201),BYTE,BYTE);
			assertFalse(b.contains(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains5() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,193),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,BYTE,BYTE,BYTE);
			assertTrue(a.contains(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains6() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,193),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(192,BYTE,BYTE,BYTE);
			assertFalse(b.contains(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains7() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,193),BYTE,BYTE,BYTE);
			assertTrue(a.contains(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter1() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,195),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(193, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = new IPv4Interval(new Interval(193, 195),BYTE,BYTE,BYTE);
			assertEquals(res, a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter2() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,195),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(193, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = new IPv4Interval(new Interval(193, 195),BYTE,BYTE,BYTE);
			assertEquals(res, b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter3() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(190, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			assertEquals(res, a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter4() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(190, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			assertEquals(res, b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter5() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(195, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = IPv4Interval.EMPTY;
			assertEquals(res, a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter6() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(195, 200),BYTE,BYTE,BYTE);
			IPv4Interval res = IPv4Interval.EMPTY;
			assertEquals(res, b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter7() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval res = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			assertEquals(res, a.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void getDefaultAny() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			assertEquals(new IPv4Interval(BYTE, BYTE, BYTE, BYTE), a.getDefaultAny());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus1() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,195),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(193, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			res.add(new IPv4Interval(192, BYTE, BYTE, BYTE));
			assertEquals(res, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus2() {
		try {
			IPv4Interval a = new IPv4Interval(new Interval(192,195),BYTE,BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(193, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			res.add(new IPv4Interval(new Interval(196, 200), BYTE, BYTE, BYTE));
			assertEquals(res, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus3() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(190, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			assertEquals(res, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus4() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(190, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			res.add(new IPv4Interval(new Interval(190, 191), BYTE, BYTE, BYTE));
			res.add(new IPv4Interval(new Interval(193, 200), BYTE, BYTE, BYTE));
			res.add(new IPv4Interval(192, new Interval(0,167), BYTE, BYTE));
			res.add(new IPv4Interval(192, new Interval(181,255), BYTE, BYTE));
			assertEquals(res, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus5() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(195, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			res.add(a);
			assertEquals(res, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus6() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			IPv4Interval b = new IPv4Interval(new Interval(195, 200),BYTE,BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			res.add(b);
			assertEquals(res, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus7() {
		try {
			IPv4Interval a = new IPv4Interval(192,new Interval(168, 180),BYTE,BYTE);
			List<IPv4Interval> res = new ArrayList<IPv4Interval>();
			assertEquals(res, a.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	
	
}
