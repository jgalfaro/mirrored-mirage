package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import model.NetworkInterface;
import model.Topology;
import model.Zone;

import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import exception.IPAddressAlreadyUsedException;
import exception.IntervalException;
import exception.NetworkIntervalException;
import exception.NotInZoneException;

public class NetworkInterfaceTest {

	@Test public void testConstructor1() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120, new Interval(30, 50)));
			new NetworkInterface(new IPv4Interval(192,168,120,35), z);
			assertTrue(true);
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
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120, new Interval(30, 50)));
			new NetworkInterface(new IPv4Interval(192,168,120,29), z);
			fail("Exception should be found");
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());			
		} catch (NotInZoneException e) {
			assertTrue(true);
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());			
		}
	}

	@Test public void testGetIPaddress() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120, new Interval(30, 50)));
			NetworkInterface n = new NetworkInterface(new IPv4Interval(192,168,120,35), z);
			assertEquals(new IPv4Interval(192,168,120,35), n.getIPAddress());
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

	@Test public void testGetZone() {
		try {
			Topology t = new Topology();
			Zone z = t.addZone("zone1", new IPv4Interval(192,168,120, new Interval(30, 50)));
			NetworkInterface n = new NetworkInterface(new IPv4Interval(192,168,120,35), z);
			assertEquals(z, n.getZone());
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
