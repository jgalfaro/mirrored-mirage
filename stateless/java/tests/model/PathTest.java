package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

public class PathTest {
	
	private Topology t;
	
	@Before public void setUp() throws Exception {
		t = new Topology();
		Zone a = t.addZone("a", new IPv4Interval(192,168,124, new Interval(0, 255)));
		Zone b = t.addZone("b", new IPv4Interval(192,168,125, new Interval(0, 255)));
		Zone c = t.addZone("c", new IPv4Interval(192,168,126, new Interval(0, 255)));
		Zone d = t.addZone("d", new IPv4Interval(192,168,127, new Interval(0, 255)));
		Zone e = t.addZone("e", new IPv4Interval(192,168,128, new Interval(0, 255)));
		Zone f = t.addZone("f", new IPv4Interval(192,168,129, new Interval(0, 255)));
		Zone g = t.addZone("g", new IPv4Interval(192,168,130, new Interval(0, 255)));
		Zone h = t.addZone("h", new IPv4Interval(192,168,131, new Interval(0, 255)));
		
		Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
		s1.add(new NetworkInterface(new IPv4Interval(192,168,124,1), a));
		t.addComponent("FW1", CType.FIREWALL, s1, Math.round(Math.random()) == 1);
		
		Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
		s2.add(new NetworkInterface(new IPv4Interval(192,168,124,2), a));
		s2.add(new NetworkInterface(new IPv4Interval(192,168,125,2), b));
		t.addComponent("FW2", CType.FIREWALL, s2, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s3 = new HashSet<NetworkInterface>();
		s3.add(new NetworkInterface(new IPv4Interval(192,168,125,3), b));
		s3.add(new NetworkInterface(new IPv4Interval(192,168,131,3), h));
		t.addComponent("FW3", CType.FIREWALL, s3, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s4 = new HashSet<NetworkInterface>();
		s4.add(new NetworkInterface(new IPv4Interval(192,168,131,4), h));		
		s4.add(new NetworkInterface(new IPv4Interval(192,168,130,4), g));
		t.addComponent("FW4", CType.FIREWALL, s4, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s5 = new HashSet<NetworkInterface>();
		s5.add(new NetworkInterface(new IPv4Interval(192,168,130,5), g));
		t.addComponent("FW5", CType.FIREWALL, s5, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s6 = new HashSet<NetworkInterface>();
		s6.add(new NetworkInterface(new IPv4Interval(192,168,130,6), g));
		s6.add(new NetworkInterface(new IPv4Interval(192,168,129,6), f));
		t.addComponent("FW6", CType.FIREWALL, s6, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s7 = new HashSet<NetworkInterface>();
		s7.add(new NetworkInterface(new IPv4Interval(192,168,130,7), g));
		s7.add(new NetworkInterface(new IPv4Interval(192,168,127,7), d));
		t.addComponent("FW7", CType.FIREWALL, s7, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s8 = new HashSet<NetworkInterface>();
		s8.add(new NetworkInterface(new IPv4Interval(192,168,125,8), b));
		s8.add(new NetworkInterface(new IPv4Interval(192,168,129,8), f));
		s8.add(new NetworkInterface(new IPv4Interval(192,168,128,8), e));
		t.addComponent("FW8", CType.FIREWALL, s8, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s9 = new HashSet<NetworkInterface>();
		s9.add(new NetworkInterface(new IPv4Interval(192,168,128,9), e));
		s9.add(new NetworkInterface(new IPv4Interval(192,168,127,9), d));
		s9.add(new NetworkInterface(new IPv4Interval(192,168,126,9), c));
		t.addComponent("FW9", CType.FIREWALL, s9, Math.round(Math.random()) == 1);

		Set<NetworkInterface> s10 = new HashSet<NetworkInterface>();
		s10.add(new NetworkInterface(new IPv4Interval(192,168,125,10), b));
		s10.add(new NetworkInterface(new IPv4Interval(192,168,126,10), c));
		t.addComponent("FW10", CType.FIREWALL, s10, Math.round(Math.random()) == 1);
	}
	
	@Test public void testConstructor1() {
		Component c = t.getComponent("FW1");
		Path p = new Path(c);
		assertTrue(p.contains(c));
		assertFalse(p.isEmpty());
	}

	@Test public void testConstructor2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertEquals(l, p.getComponents());
		assertFalse(p.isEmpty());
	}
	
	@Test public void testConstructor3() {
		List<Component> l = new ArrayList<Component>();
		Path p = new Path(l);
		assertTrue(p.isEmpty());
	}

	@Test public void equals1() {
		List<Component> l1 = new ArrayList<Component>();
		l1.add(t.getComponent("FW1"));
		l1.add(t.getComponent("FW2"));
		List<Component> l2 = new ArrayList<Component>();
		l2.add(t.getComponent("FW1"));
		l2.add(t.getComponent("FW2"));
		Path p1 = new Path(l1);
		Path p2 = new Path(l2);
		assertEquals(p1, p2);
	}
	
	@Test public void equals2() {
		List<Component> l1 = new ArrayList<Component>();
		l1.add(t.getComponent("FW2"));
		l1.add(t.getComponent("FW1"));
		List<Component> l2 = new ArrayList<Component>();
		l2.add(t.getComponent("FW1"));
		l2.add(t.getComponent("FW2"));
		Path p1 = new Path(l1);
		Path p2 = new Path(l2);
		assertNotSame(p1, p2);
	}
	
	@Test public void add1() {
		Component c = t.getComponent("FW1");
		Path p = new Path(c);
		p = p.add(t.getComponent("FW2"));
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		Path p2 = new Path(l);
		assertEquals(p2, p);
	}

	@Test public void add2() {
		Component c = t.getComponent("FW1");
		Path p = new Path(c);
		p = p.add(t.getComponent("FW3"));	// FW1 and FW3 not connected
		assertNull(p);
	}

	@Test public void add3() {
		Component c = t.getComponent("FW1");
		Path p = new Path(c);
		p = p.add(t.getComponent("FW2"));
		p = p.add(t.getComponent("FW3"));
		assertNotNull(p);
		p = p.add(t.getComponent("FW2"));	// FW2 already in the path
		assertNull(p);
	}
	
	@Test public void reverse() {
		List<Component> l1 = new ArrayList<Component>();
		l1.add(t.getComponent("FW1"));
		l1.add(t.getComponent("FW2"));
		l1.add(t.getComponent("FW3"));
		Path p1 = new Path(l1);
		List<Component> l2 = new ArrayList<Component>();
		l2.add(t.getComponent("FW3"));
		l2.add(t.getComponent("FW2"));
		l2.add(t.getComponent("FW1"));
		Path p2 = new Path(l2);
		assertEquals(p2, p1.reverse());
	}

	@Test public void contains1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertTrue(p.contains(t.getComponent("FW2")));
	}
	
	@Test public void contains2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertFalse(p.contains(t.getComponent("FW4")));
	}
	
	@Test public void lenght1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertEquals(3, p.length());
	}
	
	@Test public void first1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertEquals(t.getComponent("FW1"), p.first());
	}

	@Test public void last1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		assertEquals(t.getComponent("FW3"), p.last());
	}

	@Test public void head1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.head(t.getComponent("FW3"));
		List<Component> l3 = new ArrayList<Component>();
		l3.add(t.getComponent("FW1"));
		l3.add(t.getComponent("FW2"));
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}
	
	@Test public void head2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.head(t.getComponent("FW2"));
		List<Component> l3 = new ArrayList<Component>();
		l3.add(t.getComponent("FW1"));
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}

	@Test public void head3() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.head(t.getComponent("FW1"));
		List<Component> l3 = new ArrayList<Component>();
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}
	
	@Test public void tail1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.tail(t.getComponent("FW1"));
		List<Component> l3 = new ArrayList<Component>();
		l3.add(t.getComponent("FW2"));
		l3.add(t.getComponent("FW3"));
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}
	
	@Test public void tail2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.tail(t.getComponent("FW2"));
		List<Component> l3 = new ArrayList<Component>();
		l3.add(t.getComponent("FW3"));
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}

	@Test public void tail3() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW1"));
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW3"));
		Path p = new Path(l);
		Path p2 = p.tail(t.getComponent("FW3"));
		List<Component> l3 = new ArrayList<Component>();
		Path p3 = new Path(l3);
		assertEquals(p3, p2);
	}

	@Test public void isMinimalRoute1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW6"));
		l.add(t.getComponent("FW7"));
		Path p = new Path(l);
		assertTrue(p.isMinimalRoute());
	}
	
	@Test public void isMinimalRoute2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW6"));
		l.add(t.getComponent("FW7"));
		l.add(t.getComponent("FW9"));
		Path p = new Path(l);
		assertFalse(p.isMinimalRoute());
	}

	@Test public void isMinimalRoute3() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW9"));
		Path p = new Path(l);
		assertTrue(p.isMinimalRoute());
	}

	@Test public void route1() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW6"));
		l.add(t.getComponent("FW7"));
		l.add(t.getComponent("FW9"));
		Path p = new Path(l);
		assertTrue(p.route(t.getZone("a"), t.getZone("d")));
	}
	
	@Test public void route2() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW6"));
		l.add(t.getComponent("FW7"));
		l.add(t.getComponent("FW9"));
		Path p = new Path(l);
		assertFalse(p.route(t.getZone("d"), t.getZone("a")));
	}
	
	@Test public void route3() {
		List<Component> l = new ArrayList<Component>();
		l.add(t.getComponent("FW2"));
		l.add(t.getComponent("FW8"));
		l.add(t.getComponent("FW6"));
		l.add(t.getComponent("FW7"));
		l.add(t.getComponent("FW9"));
		Path p = new Path(l);
		assertTrue(p.route(t.getZone("b"), t.getZone("c")));
	}


	
}
