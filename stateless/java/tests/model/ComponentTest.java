package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashSet;
import java.util.Set;

import model.CType;
import model.Component;
import model.NetworkInterface;
import model.Topology;
import model.Zone;

import org.junit.Test;

import util.IPv4Interval;
import exception.IPAddressAlreadyUsedException;
import exception.IntervalException;
import exception.NetworkIntervalException;
import exception.NotInZoneException;

public class ComponentTest {

	@Test public void testConstructor1() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			NetworkInterface n = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z);
			Set<NetworkInterface> s = new HashSet<NetworkInterface>();
			s.add(n);
			Component c = t.addComponent("FW1", CType.FIREWALL, s);
			assertEquals("FW1", c.getName());
			assertEquals(CType.FIREWALL, c.getType());
			assertEquals(s, c.getNetworkInterfaces());
			assertTrue(c.isAdjacent(z));
			assertTrue(c.getRules().isEmpty());
			assertEquals(false, c.getDefaultPolicy());
			assertEquals(t, c.getTopology());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testConstructor2() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			NetworkInterface n = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z);
			Set<NetworkInterface> s = new HashSet<NetworkInterface>();
			s.add(n);
			Component c = t.addComponent("NIDS1", CType.NIDS, s, true);
			assertEquals("NIDS1", c.getName());
			assertEquals(CType.NIDS, c.getType());
			assertEquals(s, c.getNetworkInterfaces());
			assertTrue(c.isAdjacent(z));
			assertTrue(c.getRules().isEmpty());
			assertEquals(true, c.getDefaultPolicy());
			assertEquals(t, c.getTopology());
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConstructor3() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			NetworkInterface n1 = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z);
			NetworkInterface n2 = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z);
			Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
			s1.add(n1);
			Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
			s2.add(n2);
			t.addComponent("FW1", CType.FIREWALL, s1);
			t.addComponent("FW2", CType.FIREWALL, s2);
			fail("Exception should be found");
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			assertTrue(true);
		}
	}
	
	@Test public void testConnected1() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			NetworkInterface n1 = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z);
			NetworkInterface n2 = new NetworkInterface(new IPv4Interval(192, 168, 120, 113), z);
			Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
			s1.add(n1);
			Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
			s2.add(n2);
			Component c1 = t.addComponent("FW1", CType.FIREWALL, s1);
			Component c2 = t.addComponent("FW2", CType.FIREWALL, s2);
			assertTrue(c1.isConnected(c2));
			assertTrue(c2.isConnected(c1));
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}

	@Test public void testConnected2() {
		try {
			Topology t = new Topology();
			Zone z1 = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			Zone z2 = t.addZone("zone2", new IPv4Interval(192,168,121,IPv4Interval.BYTE));
			NetworkInterface n1 = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z1);
			NetworkInterface n2 = new NetworkInterface(new IPv4Interval(192, 168, 121, 113), z2);
			Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
			s1.add(n1);
			Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
			s2.add(n2);
			Component c1 = t.addComponent("FW1", CType.FIREWALL, s1);
			Component c2 = t.addComponent("FW2", CType.FIREWALL, s2);
			assertFalse(c1.isConnected(c2));
			assertFalse(c2.isConnected(c1));
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}
	
	@Test public void testAdjacent1() {
		try {
			Topology t = new Topology();
			Zone z1 = t.addZone("zone1", new IPv4Interval(192,168,120,IPv4Interval.BYTE));
			Zone z2 = t.addZone("zone2", new IPv4Interval(192,168,121,IPv4Interval.BYTE));
			NetworkInterface n1 = new NetworkInterface(new IPv4Interval(192, 168, 120, 111), z1);
			Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
			s1.add(n1);
			Component c1 = t.addComponent("FW1", CType.FIREWALL, s1);
			assertTrue(c1.isAdjacent(z1));
			assertFalse(c1.isAdjacent(z2));
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}
	}


	
}
