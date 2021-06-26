package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import model.CType;
import model.Component;
import model.NetworkInterface;
import model.Path;
import model.Topology;
import model.Zone;

import org.junit.Before;
import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import exception.IntervalException;

public class TopologyTest {

	private Topology t;
	private	Component c1;
	private	Component c2;
	private	Component c3;
	private	Component c4;
	private	Component c5;
	private	Component c6;
	private	Component c7;
	private	Component c8;
	private	Component c9;
	private	Component c10;
	private Zone za;
	private Zone zb;
	private Zone zc;
	private Zone zd;
	private Zone ze;
	private Zone zf;
	private Zone zg;
	private Zone zh;
	
	@Before public void setUp() throws Exception {
		t = new Topology();
		za = t.addZone("a", new IPv4Interval(192,168,124, new Interval(0, 255)));
		zb = t.addZone("b", new IPv4Interval(192,168,125, new Interval(0, 255)));
		zc = t.addZone("c", new IPv4Interval(192,168,126, new Interval(0, 255)));
		zd = t.addZone("d", new IPv4Interval(192,168,127, new Interval(0, 255)));
		ze = t.addZone("e", new IPv4Interval(192,168,128, new Interval(0, 255)));
		zf = t.addZone("f", new IPv4Interval(192,168,129, new Interval(0, 255)));
		zg = t.addZone("g", new IPv4Interval(192,168,130, new Interval(0, 255)));
		zh = t.addZone("h", new IPv4Interval(192,168,131, new Interval(0, 255)));
		
		Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
		s1.add(new NetworkInterface(new IPv4Interval(192,168,124,1), za));
		c1 = t.addComponent("FW1", CType.FIREWALL, s1, Math.round(Math.random()) == 1);
		
		Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
		s2.add(new NetworkInterface(new IPv4Interval(192,168,124,2), za));
		s2.add(new NetworkInterface(new IPv4Interval(192,168,125,2), zb));
		c2 = t.addComponent("FW2", CType.FIREWALL, s2, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s3 = new HashSet<NetworkInterface>();
		s3.add(new NetworkInterface(new IPv4Interval(192,168,125,3), zb));
		s3.add(new NetworkInterface(new IPv4Interval(192,168,131,3), zh));
		c3 = t.addComponent("FW3", CType.FIREWALL, s3, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s4 = new HashSet<NetworkInterface>();
		s4.add(new NetworkInterface(new IPv4Interval(192,168,131,4), zh));		
		s4.add(new NetworkInterface(new IPv4Interval(192,168,130,4), zg));
		c4 = t.addComponent("FW4", CType.FIREWALL, s4, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s5 = new HashSet<NetworkInterface>();
		s5.add(new NetworkInterface(new IPv4Interval(192,168,130,5), zg));
		c5 = t.addComponent("FW5", CType.FIREWALL, s5, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s6 = new HashSet<NetworkInterface>();
		s6.add(new NetworkInterface(new IPv4Interval(192,168,130,6), zg));
		s6.add(new NetworkInterface(new IPv4Interval(192,168,129,6), zf));
		c6 = t.addComponent("FW6", CType.FIREWALL, s6, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s7 = new HashSet<NetworkInterface>();
		s7.add(new NetworkInterface(new IPv4Interval(192,168,130,7), zg));
		s7.add(new NetworkInterface(new IPv4Interval(192,168,127,7), zd));
		c7 = t.addComponent("FW7", CType.FIREWALL, s7, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s8 = new HashSet<NetworkInterface>();
		s8.add(new NetworkInterface(new IPv4Interval(192,168,125,8), zb));
		s8.add(new NetworkInterface(new IPv4Interval(192,168,129,8), zf));
		s8.add(new NetworkInterface(new IPv4Interval(192,168,128,8), ze));
		c8 = t.addComponent("FW8", CType.FIREWALL, s8, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s9 = new HashSet<NetworkInterface>();
		s9.add(new NetworkInterface(new IPv4Interval(192,168,128,9), ze));
		s9.add(new NetworkInterface(new IPv4Interval(192,168,127,9), zd));
		s9.add(new NetworkInterface(new IPv4Interval(192,168,126,9), zc));
		c9 = t.addComponent("FW9", CType.FIREWALL, s9, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s10 = new HashSet<NetworkInterface>();
		s10.add(new NetworkInterface(new IPv4Interval(192,168,125,10), zb));
		s10.add(new NetworkInterface(new IPv4Interval(192,168,126,10), zc));
		c10 = t.addComponent("FW10", CType.FIREWALL, s10, Math.round(Math.random()) == 1);
	}

	@Test public void getComponent() {
		assertEquals(c1, t.getComponent("FW1"));
		assertEquals(c2, t.getComponent("FW2"));
		assertEquals(c3, t.getComponent("FW3"));
		assertEquals(c4, t.getComponent("FW4"));
		assertEquals(c5, t.getComponent("FW5"));
		assertEquals(c6, t.getComponent("FW6"));
		assertEquals(c7, t.getComponent("FW7"));
		assertEquals(c8, t.getComponent("FW8"));
		assertEquals(c9, t.getComponent("FW9"));
		assertEquals(c10, t.getComponent("FW10"));
		assertEquals(null, t.getComponent("FW11"));
	}
	
	@Test public void getZone() {
		assertEquals(za, t.getZone("a"));
		assertEquals(zb, t.getZone("b"));
		assertEquals(zc, t.getZone("c"));
		assertEquals(zd, t.getZone("d"));
		assertEquals(ze, t.getZone("e"));
		assertEquals(zf, t.getZone("f"));
		assertEquals(zg, t.getZone("g"));
		assertEquals(zh, t.getZone("h"));
		assertEquals(null, t.getZone("i"));
	}

	@Test public void getZones() {
		Set<Zone> s = new HashSet<Zone>();
		s.add(za);
		s.add(zb);
		s.add(zc);
		s.add(zd);
		s.add(ze);
		s.add(zf);
		s.add(zg);
		s.add(zh);
		Collection<Zone> col = t.getZones();
		assertTrue(col.containsAll(s));
		assertTrue(s.containsAll(col));
	}
	
	@Test public void getComponents() {
		Set<Component> s = new HashSet<Component>();
		s.add(c1);
		s.add(c2);
		s.add(c3);
		s.add(c4);
		s.add(c5);
		s.add(c6);
		s.add(c7);
		s.add(c8);
		s.add(c9);
		s.add(c10);
		Collection<Component> col = t.getComponents();
		assertTrue(col.containsAll(s));
		assertTrue(s.containsAll(col));
	}

	@Test public void getZoneFromAddress() {
		try {
			assertEquals(za, t.getZoneFromAddress(new IPv4Interval(192, 168, 124, 10)));
			assertEquals(zb, t.getZoneFromAddress(new IPv4Interval(192, 168, 125, new Interval(0,200))));
			assertEquals(zc, t.getZoneFromAddress(new IPv4Interval(192, 168, 126, 150)));
			assertEquals(zd, t.getZoneFromAddress(new IPv4Interval(192, 168, 127, 45)));
			assertEquals(ze, t.getZoneFromAddress(new IPv4Interval(192, 168, 128, 10)));
			assertEquals(zf, t.getZoneFromAddress(new IPv4Interval(192, 168, 129, 60)));
			assertEquals(zg, t.getZoneFromAddress(new IPv4Interval(192, 168, 130, new Interval(56,60))));
			assertEquals(zh, t.getZoneFromAddress(new IPv4Interval(192, 168, 131, 10)));
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}
	
	@Test public void minimal_routeAB() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2));
		assertEquals(s, t.minimal_route(za, zb));
	}

	@Test public void minimal_routeAC() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10));
		s.add(new Path(c2).add(c8).add(c9));
		s.add(new Path(c2).add(c3).add(c4).add(c7).add(c9));
		assertEquals(s, t.minimal_route(za, zc));
	}
	
	@Test public void minimal_routeAD() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10).add(c9));
		s.add(new Path(c2).add(c8).add(c6).add(c7));
		s.add(new Path(c2).add(c8).add(c9));
		s.add(new Path(c2).add(c3).add(c4).add(c7));
		assertEquals(s, t.minimal_route(za, zd));
	}

	@Test public void minimal_routeAE() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10).add(c9));
		s.add(new Path(c2).add(c8));
		s.add(new Path(c2).add(c3).add(c4).add(c7).add(c9));
		assertEquals(s, t.minimal_route(za, ze));
	}

	@Test public void minimal_routeAF() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c8));
		s.add(new Path(c2).add(c3).add(c4).add(c6));
		s.add(new Path(c2).add(c10).add(c9).add(c7).add(c6));
		assertEquals(s, t.minimal_route(za, zf));
	}

	@Test public void minimal_routeEG() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c8).add(c6));
		s.add(new Path(c9).add(c7));
		s.add(new Path(c8).add(c3).add(c4));
		s.add(new Path(c9).add(c10).add(c3).add(c4));
		assertEquals(s, t.minimal_route(ze, zg));
	}

	@Test public void minimal_routeBA() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).reverse());
		assertEquals(s, t.minimal_route(zb, za));
	}

	@Test public void minimal_routeCA() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10).reverse());
		s.add(new Path(c2).add(c8).add(c9).reverse());
		s.add(new Path(c2).add(c3).add(c4).add(c7).add(c9).reverse());
		assertEquals(s, t.minimal_route(zc, za));
	}
	
	@Test public void minimal_routeDA() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10).add(c9).reverse());
		s.add(new Path(c2).add(c8).add(c6).add(c7).reverse());
		s.add(new Path(c2).add(c8).add(c9).reverse());
		s.add(new Path(c2).add(c3).add(c4).add(c7).reverse());
		assertEquals(s, t.minimal_route(zd, za));
	}

	@Test public void minimal_routeEA() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c10).add(c9).reverse());
		s.add(new Path(c2).add(c8).reverse());
		s.add(new Path(c2).add(c3).add(c4).add(c7).add(c9).reverse());
		assertEquals(s, t.minimal_route(ze, za));
	}

	@Test public void minimal_routeFA() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c2).add(c8).reverse());
		s.add(new Path(c2).add(c3).add(c4).add(c6).reverse());
		s.add(new Path(c2).add(c10).add(c9).add(c7).add(c6).reverse());
		assertEquals(s, t.minimal_route(zf, za));
	}

	@Test public void minimal_routeGE() {
		Set<Path> s = new HashSet<Path>();
		s.add(new Path(c8).add(c6).reverse());
		s.add(new Path(c9).add(c7).reverse());
		s.add(new Path(c8).add(c3).add(c4).reverse());
		s.add(new Path(c9).add(c10).add(c3).add(c4).reverse());
		assertEquals(s, t.minimal_route(zg, ze));
	}
	
	
}
