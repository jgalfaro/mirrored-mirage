package tests.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import util.Interval;
import exception.IntervalException;

public class IntervalTest {

	@Test public void testConstrutor1() {
		try {
			Interval i = new Interval(0);
			assertEquals(0, i.getBegin());
			assertEquals(0, i.getEnd());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testConstrutor2() {
		try {
			Interval i = new Interval(654321);
			assertEquals(654321, i.getBegin());
			assertEquals(654321, i.getEnd());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstrutor3() {
		try {
			new Interval(-1);
			fail("Exception should be found");
		} catch (IntervalException e) {
			assertTrue(true);
		}
	}

	@Test public void testConstrutor4() {
		try {
			Interval i = new Interval(15, 30);
			assertEquals(15, i.getBegin());
			assertEquals(30, i.getEnd());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstrutor5() {
		try {
			Interval i = new Interval(60, 60);
			assertEquals(60, i.getBegin());
			assertEquals(60, i.getEnd());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstrutor6() {
		try {
			new Interval(-10, 40);
			fail("Exception should be found");
		} catch (IntervalException e) {
			assertTrue(true);
		}
	}

	@Test public void testConstrutor7() {
		try {
			new Interval(30, 20);
			fail("Exception should be found");
		} catch (IntervalException e) {
			assertTrue(true);
		}
	}

	@Test public void testIsEmpty1() {
		try {
			Interval i = new Interval(60, 60);
			assertFalse(i.isEmpty());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testIsEmpty2() {
		try {
			Interval i = new Interval(50, 60);
			assertFalse(i.isEmpty());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testIsEmpty3() {
		assertTrue(Interval.EMPTY.isEmpty());
	}
	
	@Test public void testIsSingleton1() {
		try {
			Interval i = new Interval(60, 60);
			assertTrue(i.isSingleton());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testIsSingleton2() {
		try {
			Interval i = new Interval(50, 60);
			assertFalse(i.isSingleton());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains1() {
		try {
			Interval i = new Interval(50, 60);
			assertTrue(i.contains(50));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains2() {
		try {
			Interval i = new Interval(50, 60);
			assertTrue(i.contains(60));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains3() {
		try {
			Interval i = new Interval(50, 60);
			assertTrue(i.contains(53));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains4() {
		try {
			Interval i = new Interval(60, 60);
			assertTrue(i.contains(60));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains5() {
		try {
			Interval i = new Interval(50, 60);
			assertFalse(i.contains(62));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains6() {
		try {
			Interval i = new Interval(60, 60);
			assertFalse(i.contains(62));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testContains7() {
		assertFalse(Interval.EMPTY.contains(50));
	}

	@Test public void testEquals1() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(30, 61);
			assertTrue(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testEquals2() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(30, 61);
			assertTrue(b.equals(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testEquals3() {
		try {
			Interval a = new Interval(30, 61);
			assertTrue(a.equals(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testEquals4() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(30, 62);
			assertFalse(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testEquals5() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(62, 70);
			assertFalse(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testEquals6() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = Interval.EMPTY;
			assertFalse(a.equals(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter1() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(62, 70);
			assertEquals(Interval.EMPTY, a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter2() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(62, 70);
			assertEquals(Interval.EMPTY, b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}


	@Test public void testInter3() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = Interval.EMPTY;
			assertEquals(Interval.EMPTY, a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter4() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = Interval.EMPTY;
			assertEquals(Interval.EMPTY, b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter5() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(61, 70);
			assertEquals(new Interval(61), a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter6() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(61, 70);
			assertEquals(new Interval(61), b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter7() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 70);
			assertEquals(new Interval(61, 65), a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter8() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 70);
			assertEquals(new Interval(61, 65), b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testInter9() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 64);
			assertEquals(new Interval(61, 64), a.inter(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testInter10() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 64);
			assertEquals(new Interval(61, 64), b.inter(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus1() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(62, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(a);
			assertEquals(minus, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus2() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(62, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(b);
			assertEquals(minus, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}


	@Test public void testMinus3() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = Interval.EMPTY;
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(a);
			assertEquals(minus, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus4() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = Interval.EMPTY;
			List<Interval> minus = new ArrayList<Interval>();
			assertEquals(minus, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus5() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(61, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(new Interval(30, 60));
			assertEquals(minus, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus6() {
		try {
			Interval a = new Interval(30, 61);
			Interval b = new Interval(61, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(new Interval(62, 70));
			assertEquals(minus, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus7() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(new Interval(30, 60));
			assertEquals(minus, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus8() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 70);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(new Interval(66, 70));
			assertEquals(minus, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testMinus9() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 64);
			List<Interval> minus = new ArrayList<Interval>();
			minus.add(new Interval(30, 60));
			minus.add(new Interval(65, 65));
			assertEquals(minus, a.minus(b));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testMinus10() {
		try {
			Interval a = new Interval(30, 65);
			Interval b = new Interval(61, 64);
			List<Interval> minus = new ArrayList<Interval>();
			assertEquals(minus, b.minus(a));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testGetDefaultAny() {
		try {
			Interval a = new Interval(30, 65);
			assertEquals(new Interval(Integer.MAX_VALUE), a.getDefaultAny());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	
	
}
