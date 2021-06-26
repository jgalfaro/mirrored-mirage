package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.HashSet;
import java.util.Set;

import model.Component;
import model.Topology;
import model.Zone;

import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import exception.IntervalException;
import exception.NetworkIntervalException;

public class ZoneTest {

	@Test public void getTopology() {
		Topology t = new Topology();
		try {
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,new Interval(120,125), IPv4Interval.BYTE));
			assertEquals(t, z.getTopology());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void getName() {
		Topology t = new Topology();
		try {
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,new Interval(120,125), IPv4Interval.BYTE));
			assertEquals("zone1", z.getName());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void getNetwork() {
		Topology t = new Topology();
		try {
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,new Interval(120,125), IPv4Interval.BYTE));
			Set<IPv4Interval> s = new HashSet<IPv4Interval>();
			s.add(new IPv4Interval(192,168,new Interval(120,125), IPv4Interval.BYTE));
			assertEquals(s, z.getNetwork());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void getComponents() {
		Topology t = new Topology();
		try {
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,new Interval(120,125), IPv4Interval.BYTE));
			assertEquals(new HashSet<Component>(), z.getComponents());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	
}
