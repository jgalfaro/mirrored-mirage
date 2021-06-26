package tests.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import util.PortInterval;
import exception.IntervalException;

public class PortIntervalTest {

	@Test public void testConstrutor2() {
		try {
			new PortInterval(0, PortInterval.MAX);
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstrutor3() {
		try {
			new PortInterval(PortInterval.MAX + 1);
			fail("Exception should be found");
		} catch (IntervalException e) {
			assertTrue(true);
		}
	}

	@Test public void testGetDefaultAny() {
		try {
			PortInterval a = new PortInterval(30, 65);
			assertEquals(new PortInterval(PortInterval.MAX), a.getDefaultAny());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
}
