package tests.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import model.CondElementType;
import model.Conditions;
import model.RType;
import model.Rule;

import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import util.ProtocolSet;
import exception.IntervalException;

public class RuleTest {

	@Test public void constructor1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			assertFalse(r.isIrrelevance());
			assertFalse(r.isShadowing());
			assertFalse(r.isRedundancy());
			assertEquals(Ac, r.getOrigCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}
	
	@Test public void getCondition() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions, CondElementType>>();
			s.add(Ac);
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			assertEquals(s, r.getCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}
	
	@Test public void getDecision1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			assertEquals(true, r.getDecision());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}
	
	@Test public void getDecision2() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, false);
			assertEquals(false, r.getDecision());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void getName() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			assertEquals("rule1", r.getName());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void setShadowing1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setShadowing(true);
			assertEquals(true, r.isShadowing());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}
	
	@Test public void setShadowing2() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setShadowing(false);
			assertEquals(false, r.isShadowing());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void setRedundancy1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setRedundancy(true);
			assertEquals(true, r.isRedundancy());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}
	
	@Test public void setRedundancy2() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setRedundancy(true);
			assertEquals(true, r.isRedundancy());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void setIrrelevance1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setIrrelevance(true);
			assertEquals(true, r.isIrrelevance());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void setIrrelevance2() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			r.setIrrelevance(false);
			assertEquals(false, r.isIrrelevance());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void getExclusionList1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			assertEquals(new ArrayList<Rule>(), r.getExclusionList());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void addExclusionList() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			Rule r2 = new Rule("rule2", RType.FILTERING, new HashMap<Conditions, CondElementType>(), true);
			r.addExclusionList(r2);
			List<Rule> l = new ArrayList<Rule>();
			l.add(r2);
			assertEquals(l, r.getExclusionList());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void replaceWith() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
			Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 60)));
			Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(30, 70)));
			Bc.put(Conditions.PROTOCOL, new ProtocolSet("udp"));
			Rule r2 = new Rule("rule2", RType.FILTERING, Bc, false);
			r.replaceWith(r2);
			Set<Map<Conditions, CondElementType>> s = r2.getCondition();
			assertEquals(s, r.getCondition());
			assertEquals("rule1", r.getName());
			assertEquals(true, r.getDecision());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	@Test public void getOrigCondition1() {
		try {
			Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
			Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r = new Rule("rule1", RType.FILTERING, Ac, true);
			Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
			Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 60)));
			Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(30, 70)));
			Bc.put(Conditions.PROTOCOL, new ProtocolSet("udp"));
			Rule r2 = new Rule("rule2", RType.FILTERING, Bc, false);
			r.replaceWith(r2);
			assertEquals(Ac, r.getOrigCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("Not exception should be found : " + e.getMessage());
		}		
	}

	
}
