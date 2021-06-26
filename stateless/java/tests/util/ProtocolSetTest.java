package tests.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import util.ProtocolSet;

public class ProtocolSetTest {

	@Test public void testConstrutor1() {
		ProtocolSet i = new ProtocolSet("tcp");
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");
		assertEquals(protocols, i.getProtocols());
	}
	
	@Test public void testConstrutor2() {
		Set<String> p = new HashSet<String>();
		p.add("tcp");
		ProtocolSet i = new ProtocolSet(p);
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");
		assertEquals(protocols, i.getProtocols());
	}

	@Test public void testConstrutor3() {
		Set<String> p = new HashSet<String>();
		p.add("tcp");p.add("udp");
		ProtocolSet i = new ProtocolSet(p);
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");protocols.add("udp");
		assertEquals(protocols, i.getProtocols());
	}
	
	@Test public void testGetDefaultAny() {
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");protocols.add("udp");protocols.add("icmp");
		assertEquals(protocols, ProtocolSet.ANY.getProtocols());
	}
	
	@Test public void testEquals1() {
		ProtocolSet a = new ProtocolSet("tcp");
		ProtocolSet b = new ProtocolSet("tcp");
		assertTrue(a.equals(b));
	}
	
	@Test public void testEquals2() {
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");protocols.add("udp");protocols.add("icmp");
		ProtocolSet a = new ProtocolSet(protocols);
		ProtocolSet b = ProtocolSet.ANY;
		assertTrue(a.equals(b));
	}
	
	@Test public void testEquals3() {
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");protocols.add("icmp");
		ProtocolSet a = new ProtocolSet(protocols);
		ProtocolSet b = ProtocolSet.ANY;
		assertFalse(a.equals(b));
	}
	
	@Test public void testEquals4() {
		Set<String> pA = new HashSet<String>();
		pA.add("tcp");pA.add("udp");
		ProtocolSet a = new ProtocolSet(pA);
		Set<String> pB = new HashSet<String>();
		pB.add("udp");pB.add("tcp");
		ProtocolSet b = new ProtocolSet(pB);
		assertTrue(a.equals(b));
	}
	
	@Test public void testInter1() {
		ProtocolSet a = new ProtocolSet("tcp");
		ProtocolSet b = new ProtocolSet("tcp");
		ProtocolSet r = new ProtocolSet("tcp");
		assertEquals(r, a.inter(b));
	}
	
	@Test public void testInter2() {
		ProtocolSet a = new ProtocolSet("tcp");
		ProtocolSet b = new ProtocolSet("udp");
		ProtocolSet r = new ProtocolSet(new HashSet<String>());
		assertEquals(r, a.inter(b));
	}


	@Test public void testMinus1() {
		ProtocolSet a = new ProtocolSet("tcp");
		ProtocolSet b = new ProtocolSet("udp");
		List<ProtocolSet> minus = new ArrayList<ProtocolSet>();
		minus.add(new ProtocolSet("tcp"));
		assertEquals(minus, a.minus(b));
	}

	@Test public void testMinus2() {
		ProtocolSet a = new ProtocolSet("tcp");
		ProtocolSet b = new ProtocolSet("tcp");
		List<ProtocolSet> minus = new ArrayList<ProtocolSet>();
		assertEquals(minus, a.minus(b));
	}

	@Test public void testMinus3() {
		Set<String> pA = new HashSet<String>();
		pA.add("tcp");pA.add("udp");
		ProtocolSet a = new ProtocolSet(pA);
		Set<String> pB = new HashSet<String>();
		pB.add("udp");pB.add("icmp");
		ProtocolSet b = new ProtocolSet(pB);
		List<ProtocolSet> minus = new ArrayList<ProtocolSet>();
		minus.add(new ProtocolSet("tcp"));
		assertEquals(minus, a.minus(b));
	}

	@Test public void testIsEmpty1() {
		assertFalse(new ProtocolSet("tcp").isEmpty());
	}

	@Test public void testIsEmpty2() {
		assertTrue(new ProtocolSet(new HashSet<String>()).isEmpty());
	}

	
}
