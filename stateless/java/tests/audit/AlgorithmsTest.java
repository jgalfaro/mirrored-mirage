package tests.audit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static util.IPv4Interval.BYTE;
import static util.IPv4Interval.EMPTY;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import model.CType;
import model.Component;
import model.CondElementType;
import model.Conditions;
import model.NetworkInterface;
import model.RType;
import model.Rule;
import model.Topology;
import model.Zone;

import org.junit.Test;

import util.IPv4Interval;
import util.Interval;
import util.ProtocolSet;
import util.StringField;
import audit.Algorithms;
import audit.AuditWarning;
import exception.IPAddressAlreadyUsedException;
import exception.IntervalException;
import exception.NetworkIntervalException;
import exception.NotInZoneException;

public class AlgorithmsTest {

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
	
	public void setUpTopo() throws Exception {
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
	
	public List<Rule> getTB_rules() {
		List<Rule> res = new ArrayList<Rule>();
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 50)));
			res.add(new Rule("R1", RType.ALERTING, rc1, true));
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(40, 90)));
			res.add(new Rule("R2", RType.ALERTING, rc2, false));
			Map<Conditions, CondElementType> rc3 = new HashMap<Conditions, CondElementType>();
			rc3.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(60, 100)));
			res.add(new Rule("R3", RType.ALERTING, rc3, false));
			Map<Conditions, CondElementType> rc4 = new HashMap<Conditions, CondElementType>();
			rc4.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(30, 80)));
			res.add(new Rule("R4", RType.ALERTING, rc4, true));
			Map<Conditions, CondElementType> rc5 = new HashMap<Conditions, CondElementType>();
			rc5.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 70)));
			res.add(new Rule("R5", RType.ALERTING, rc5, false));
		} catch (IntervalException e) {
			fail("No exception should be found");
		}
		return res;
	}
	
	@Test public void exclusion1() {
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			rc1.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r1 = new Rule("R1", RType.FILTERING, rc1, false);
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			rc2.put(Conditions.PROTOCOL, new ProtocolSet("udp"));
			Rule r2 = new Rule("R1", RType.FILTERING, rc2, false);
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions,CondElementType>>();
			s.add(rc1);
			assertEquals(s, Algorithms.exclusion(r1, r2).getCondition()); // r1 and r2 independent
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}
	
	@Test public void exclusion2() {
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			rc1.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			Rule r1 = new Rule("R1", RType.FILTERING, rc1, false);
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
			rc2.put(Conditions.PROTOCOL, new ProtocolSet("udp"));
			Rule r2 = new Rule("R1", RType.FILTERING, rc2, false);
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions,CondElementType>>();
			s.add(rc2);
			assertEquals(s, Algorithms.exclusion(r2, r1).getCondition()); // r2 and r1 independent
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}

	@Test public void exclusion3() {
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(20, 30)));
			Rule r1 = new Rule("R1", RType.FILTERING, rc1, false);
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			Rule r2 = new Rule("R2", RType.FILTERING, rc2, false);
			
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions,CondElementType>>();
			Map<Conditions, CondElementType> cond1 = new HashMap<Conditions, CondElementType>();
			cond1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			cond1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 19)));
			Map<Conditions, CondElementType> cond2 = new HashMap<Conditions, CondElementType>();
			cond2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			cond2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(31, 50)));
			s.add(cond1);
			s.add(cond2);
			assertEquals(s, Algorithms.exclusion(r2, r1).getCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}

	@Test public void exclusion4() {
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 40)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(20, 30)));
			Rule r1 = new Rule("R1", RType.FILTERING, rc1, false);
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			Rule r2 = new Rule("R2", RType.FILTERING, rc2, false);
			
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions,CondElementType>>();
			Map<Conditions, CondElementType> cond1 = new HashMap<Conditions, CondElementType>();
			cond1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 9)));
			cond1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			Map<Conditions, CondElementType> cond2 = new HashMap<Conditions, CondElementType>();
			cond2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(41, 50)));
			cond2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			Map<Conditions, CondElementType> cond3 = new HashMap<Conditions, CondElementType>();
			cond3.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 40)));
			cond3.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 19)));
			Map<Conditions, CondElementType> cond4 = new HashMap<Conditions, CondElementType>();
			cond4.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 40)));
			cond4.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(31, 50)));
			s.add(cond1);
			s.add(cond2);
			s.add(cond3);
			s.add(cond4);
			assertEquals(s, Algorithms.exclusion(r2, r1).getCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}

	@Test public void exclusion5() {
		try {
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
			Rule r1 = new Rule("R1", RType.FILTERING, rc1, false);
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
			Rule r2 = new Rule("R2", RType.FILTERING, rc2, false);
			
			Set<Map<Conditions, CondElementType>> s = new HashSet<Map<Conditions,CondElementType>>();
			assertEquals(s, Algorithms.exclusion(r2, r1).getCondition());
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
	}
	
	@Test public void testIrrelevance() {
		
	}
	
	@Test public void auditIntraComponent() {
		System.out.println("**** Test example 01 ****");
		try{setUpTopo();} catch (Exception e) {}
		System.out.println(AuditWarning.toString(Algorithms.intraComponentAudit(c1, getTB_rules())));
	}

	public Topology getTopoFig2() {
		Topology t = new Topology();
		try {
			Zone external = t.addZone("external", new IPv4Interval(192, 170, 26, BYTE));
			Zone unix = t.addZone("unix", new IPv4Interval(192, 170, 21, BYTE));
			Zone windows = t.addZone("windows", new IPv4Interval(192, 170, 33, BYTE));
			Zone empty = t.addZone("empty");
			windows.getVulnerabilities().add("winworm");
			unix.getVulnerabilities().add("unixworm");
			Set<NetworkInterface> nc1 = new HashSet<NetworkInterface>();
			nc1.add(new NetworkInterface(new IPv4Interval(192, 170, 26, 1), external));
			nc1.add(new NetworkInterface(EMPTY, empty));
			nc1.add(new NetworkInterface(new IPv4Interval(192, 170, 21, 1), unix));
			Component c1 = t.addComponent("C1", CType.FIREWALL, nc1);
			Set<NetworkInterface> nc2 = new HashSet<NetworkInterface>();
			nc2.add(new NetworkInterface(new IPv4Interval(192, 170, 26, 2), external));
			nc2.add(new NetworkInterface(new IPv4Interval(192, 170, 33, 2), windows));
			nc2.add(new NetworkInterface(new IPv4Interval(192, 170, 21, 2), unix));
			Component c2 = t.addComponent("C2", CType.NIDS, nc2);
			Set<NetworkInterface> nc3 = new HashSet<NetworkInterface>();
			nc3.add(new NetworkInterface(new IPv4Interval(192, 170, 21, 3), unix));
			nc3.add(new NetworkInterface(new IPv4Interval(192, 170, 33, 3), windows));
			t.addComponent("C3", CType.NIDS, nc3, false);
			Set<NetworkInterface> nc4 = new HashSet<NetworkInterface>();
			nc4.add(new NetworkInterface(EMPTY, empty));
			nc4.add(new NetworkInterface(new IPv4Interval(192, 170, 33, 4), windows));
			t.addComponent("C4", CType.NIDS, nc4, false);
			
			
			List<Rule> l1 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc1 = new HashMap<Conditions, CondElementType>();
			rc1.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, new Interval(10, 20)));
			rc1.put(Conditions.DZONE, new IPv4Interval(192, 170, 26, new Interval(50, 60)));
			rc1.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R1", RType.FILTERING, rc1, false));
			Map<Conditions, CondElementType> rc2 = new HashMap<Conditions, CondElementType>();
			rc2.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, BYTE));
			rc2.put(Conditions.DZONE, new IPv4Interval(192, 170, 33, BYTE));
			rc2.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R2", RType.FILTERING, rc2, false));
			Map<Conditions, CondElementType> rc3 = new HashMap<Conditions, CondElementType>();
			rc3.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(1, 30)));
			rc3.put(Conditions.DZONE, new IPv4Interval(192, 170, 26, new Interval(20, 45)));
			rc3.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R3", RType.FILTERING, rc3, true));
			Map<Conditions, CondElementType> rc4 = new HashMap<Conditions, CondElementType>();
			rc4.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(20, 60)));
			rc4.put(Conditions.DZONE, new IPv4Interval(192, 170, 26, new Interval(25, 35)));
			rc4.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R4", RType.FILTERING, rc4, false));
			Map<Conditions, CondElementType> rc5 = new HashMap<Conditions, CondElementType>();
			rc5.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(30, 70)));
			rc5.put(Conditions.DZONE, new IPv4Interval(192, 170, 26, new Interval(20, 45)));
			rc5.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R5", RType.FILTERING, rc5, false));
			Map<Conditions, CondElementType> rc6 = new HashMap<Conditions, CondElementType>();
			rc6.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(15, 45)));
			rc6.put(Conditions.DZONE, new IPv4Interval(192, 170, 26, new Interval(25, 30)));
			rc6.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R6", RType.FILTERING, rc6, true));
			c1.setRules(l1);
			
			List<Rule> l2 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc21 = new HashMap<Conditions, CondElementType>();
			rc21.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, BYTE));
			rc21.put(Conditions.DZONE, new IPv4Interval(192, 170, 33, BYTE));
			rc21.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc21.put(Conditions.PAYLOAD, new StringField("payload1"));
			rc21.put(Conditions.AC, new StringField("winworm"));
			l2.add(new Rule("R1", RType.ALERTING, rc21, true));
			Map<Conditions, CondElementType> rc22 = new HashMap<Conditions, CondElementType>();
			rc22.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, BYTE));
			rc22.put(Conditions.DZONE, new IPv4Interval(192, 170, 21, BYTE));
			rc22.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc22.put(Conditions.PAYLOAD, new StringField("payload2"));
			rc22.put(Conditions.AC, new StringField("winworm"));
			l2.add(new Rule("R2", RType.ALERTING, rc22, true));
			Map<Conditions, CondElementType> rc23 = new HashMap<Conditions, CondElementType>();
			rc23.put(Conditions.SZONE, new IPv4Interval(192, 170, 33, BYTE));
			rc23.put(Conditions.DZONE, new IPv4Interval(192, 170, 21, BYTE));
			rc23.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc23.put(Conditions.PAYLOAD, new StringField("payload3"));
			rc23.put(Conditions.AC, new StringField("unixworm"));
			l2.add(new Rule("R3", RType.ALERTING, rc23, true));
			Map<Conditions, CondElementType> rc24 = new HashMap<Conditions, CondElementType>();
			rc24.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, new Interval(1, 30)));
			rc24.put(Conditions.DZONE, new IPv4Interval(192, 170, 21, new Interval(20, 45)));
			rc24.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc24.put(Conditions.PAYLOAD, new StringField("payload4"));
			rc24.put(Conditions.AC, new StringField("unixworm"));
			l2.add(new Rule("R4", RType.ALERTING, rc24, true));
			Map<Conditions, CondElementType> rc25 = new HashMap<Conditions, CondElementType>();
			rc25.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, new Interval(20, 60)));
			rc25.put(Conditions.DZONE, new IPv4Interval(192, 170, 21, new Interval(25, 35)));
			rc25.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc25.put(Conditions.PAYLOAD, new StringField("payload5"));
			rc25.put(Conditions.AC, new StringField("unixworm"));
			l2.add(new Rule("R5", RType.ALERTING, rc25, true));
			Map<Conditions, CondElementType> rc26 = new HashMap<Conditions, CondElementType>();
			rc26.put(Conditions.SZONE, new IPv4Interval(192, 170, 26, new Interval(10, 40)));
			rc26.put(Conditions.DZONE, new IPv4Interval(192, 170, 21, new Interval(25, 30)));
			rc26.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			rc26.put(Conditions.PAYLOAD, new StringField("payload6"));
			rc26.put(Conditions.AC, new StringField("unixworm"));
			l2.add(new Rule("R6", RType.ALERTING, rc26, true));
			c2.setRules(l2);
			
		} catch (IntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		} catch (NetworkIntervalException e) {
			e.printStackTrace();
			fail("No exception should be found");
		} catch (NotInZoneException e) {
			e.printStackTrace();
			fail("No exception should be found");
		} catch (IPAddressAlreadyUsedException e) {
			e.printStackTrace();
			fail("No exception should be found");
		}
		return t;
	}
	
	@Test public void auditIntraComponentFig2() {
		System.out.println("**** Test example 2 ****");
		Topology t = getTopoFig2();
		t.setKeepShortestRoutes(true);
		for(Component c : t.getComponents()) {
			if(!c.getRules().isEmpty()) {
				System.out.println("** Audit " + c.getName() + " **");
				System.out.println(AuditWarning.toString(Algorithms.intraComponentAudit(c, c.getRules())));
			}
		}
		/*Component c = t.getComponent("C1");
		p.println("** Audit " + c.getName() + " **");
		Algorithms.intraComponentAudit(c, c.getRules(), p);*/
	}

	public Topology getTopoFig4() {
		Topology t = new Topology();
		try {
			Zone E1 = t.addZone("E1", new IPv4Interval(200, 160, new Interval(1,2), BYTE));
			Zone E2 = t.addZone("E2", new IPv4Interval(192, 170, new Interval(21,23), BYTE));
			Zone P1 = t.addZone("P1", new IPv4Interval(10, 0, 26, BYTE));
			P1.getNetwork().add(new IPv4Interval(10, 0, 28, BYTE));
			Zone P2 = t.addZone("P2", new IPv4Interval(10, 0, new Interval(24,25), BYTE));
			P2.getNetwork().add(new IPv4Interval(10, 0, 27, BYTE));
			Zone P3 = t.addZone("P3", new IPv4Interval(10, 0, new Interval(34,36), BYTE));
			Zone P4 = t.addZone("P4", new IPv4Interval(10, 0, new Interval(31,33), BYTE));
			Zone P5 = t.addZone("P5", new IPv4Interval(10, 0, 16, BYTE));
			
			Zone bn = t.addZone("bn");
			Zone bw = t.addZone("bw");
			Zone be1 = t.addZone("be1");
			Zone be2 = t.addZone("be2");
			Zone bs1 = t.addZone("bs1");
			Zone bs2 = t.addZone("bs2");
			
			Set<NetworkInterface> nc1 = new HashSet<NetworkInterface>();
			nc1.add(new NetworkInterface(EMPTY, bn));
			nc1.add(new NetworkInterface(EMPTY, bw));
			nc1.add(new NetworkInterface(new IPv4Interval(200, 160, 1, 1), E1));
			Component c1 = t.addComponent("C1", CType.FIREWALL, nc1, true);

			Set<NetworkInterface> nc2 = new HashSet<NetworkInterface>();
			nc2.add(new NetworkInterface(EMPTY, bw));
			nc2.add(new NetworkInterface(EMPTY, bs1));
			nc2.add(new NetworkInterface(EMPTY, bs2));
			nc2.add(new NetworkInterface(new IPv4Interval(10, 0, 16, 0), P5));
			nc2.add(new NetworkInterface(new IPv4Interval(10, 0, 31, 1), P4));
			Component c2 = t.addComponent("C2", CType.FIREWALL, nc2, true);
			
			Set<NetworkInterface> nc3 = new HashSet<NetworkInterface>();
			nc3.add(new NetworkInterface(EMPTY, bn));
			nc3.add(new NetworkInterface(new IPv4Interval(10, 0, 26, 1), P1));
			Component c3 = t.addComponent("C3", CType.NIDS, nc3, true);

			Set<NetworkInterface> nc4 = new HashSet<NetworkInterface>();
			nc4.add(new NetworkInterface(EMPTY, bw));
			nc4.add(new NetworkInterface(EMPTY, be1));
			nc4.add(new NetworkInterface(new IPv4Interval(10, 0, 24, 1), P2));
			Component c4 = t.addComponent("C4", CType.NIDS, nc4);

			Set<NetworkInterface> nc5 = new HashSet<NetworkInterface>();
			nc5.add(new NetworkInterface(EMPTY, bs1));
			nc5.add(new NetworkInterface(EMPTY, be2));
			nc5.add(new NetworkInterface(new IPv4Interval(10, 0, 34, 1), P3));
			Component c5 = t.addComponent("C5", CType.FIREWALL, nc5);
			
			Set<NetworkInterface> nc6 = new HashSet<NetworkInterface>();
			nc6.add(new NetworkInterface(EMPTY, bn));
			nc6.add(new NetworkInterface(EMPTY, be1));
			nc6.add(new NetworkInterface(EMPTY, be2));
			nc6.add(new NetworkInterface(EMPTY, bs2));
			nc6.add(new NetworkInterface(new IPv4Interval(192, 170, 21, 1), E2));
			Component c6 = t.addComponent("C6", CType.FIREWALL, nc6);
			
			// C1
			List<Rule> l1 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc11 = new HashMap<Conditions, CondElementType>();
			rc11.put(Conditions.SZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc11.put(Conditions.DZONE, new IPv4Interval(10, 0, 16, BYTE));
			rc11.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R1", RType.FILTERING, rc11, false));
			Map<Conditions, CondElementType> rc12 = new HashMap<Conditions, CondElementType>();
			rc12.put(Conditions.SZONE, new IPv4Interval(200, 160, 2, BYTE));
			rc12.put(Conditions.DZONE, new IPv4Interval(10, 0, 16, BYTE));
			rc12.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R2", RType.FILTERING, rc12, false));
			Map<Conditions, CondElementType> rc13 = new HashMap<Conditions, CondElementType>();
			rc13.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(20,33)));
			rc13.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, new Interval(20,30)));
			rc13.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R3", RType.FILTERING, rc13, false));
			Map<Conditions, CondElementType> rc14 = new HashMap<Conditions, CondElementType>();
			rc14.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(60,80)));
			rc14.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, new Interval(20,30)));
			rc14.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R4", RType.FILTERING, rc14, false));
			Map<Conditions, CondElementType> rc15 = new HashMap<Conditions, CondElementType>();
			rc15.put(Conditions.SZONE, new IPv4Interval(10, 0, 33, new Interval(0,30)));
			rc15.put(Conditions.DZONE, new IPv4Interval(200, 160, 2, new Interval(10,30)));
			rc15.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R5", RType.FILTERING, rc15, false));
			Map<Conditions, CondElementType> rc16 = new HashMap<Conditions, CondElementType>();
			rc16.put(Conditions.SZONE, new IPv4Interval(10, 0, 31, new Interval(10,20)));
			rc16.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc16.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R6", RType.FILTERING, rc16, false));
			Map<Conditions, CondElementType> rc17 = new HashMap<Conditions, CondElementType>();
			rc17.put(Conditions.SZONE, new IPv4Interval(10, 0, 33, BYTE));
			rc17.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, new Interval(10,12)));
			rc17.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l1.add(new Rule("R7", RType.FILTERING, rc17, false));
			c1.setRules(l1);
			
			// C2
			List<Rule> l2 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc21 = new HashMap<Conditions, CondElementType>();
			rc21.put(Conditions.SZONE, new IPv4Interval(10, 0, 31, new Interval(15,17)));
			rc21.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc21.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R1", RType.FILTERING, rc21, false));
			Map<Conditions, CondElementType> rc22 = new HashMap<Conditions, CondElementType>();
			rc22.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, new Interval(0,70)));
			rc22.put(Conditions.DZONE, new IPv4Interval(10, 0, 35, BYTE));
			rc22.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R2", RType.FILTERING, rc22, false));
			Map<Conditions, CondElementType> rc23 = new HashMap<Conditions, CondElementType>();
			rc23.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, new Interval(0,70)));
			rc23.put(Conditions.DZONE, new IPv4Interval(200, 160, 2, BYTE));
			rc23.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R3", RType.FILTERING, rc23, false));
			Map<Conditions, CondElementType> rc24 = new HashMap<Conditions, CondElementType>();
			rc24.put(Conditions.SZONE, new IPv4Interval(10, 0, 33, BYTE));
			rc24.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc24.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R4", RType.FILTERING, rc24, false));
			Map<Conditions, CondElementType> rc25 = new HashMap<Conditions, CondElementType>();
			rc25.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, new Interval(0,70)));
			rc25.put(Conditions.DZONE, new IPv4Interval(10, 0, 25, BYTE));
			rc25.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R5", RType.FILTERING, rc25, false));
			Map<Conditions, CondElementType> rc26 = new HashMap<Conditions, CondElementType>();
			rc26.put(Conditions.SZONE, new IPv4Interval(200, 160, new Interval(1,2), BYTE));
			rc26.put(Conditions.DZONE, new IPv4Interval(10, 0, 16, BYTE));
			rc26.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l2.add(new Rule("R6", RType.FILTERING, rc26, false));
			c2.setRules(l2);
			
			// C3
			List<Rule> l3 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc31 = new HashMap<Conditions, CondElementType>();
			rc31.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(20,33)));
			rc31.put(Conditions.DZONE, new IPv4Interval(10, 0, 26, new Interval(20,30)));
			rc31.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l3.add(new Rule("R1", RType.ALERTING, rc31, false));
			Map<Conditions, CondElementType> rc32 = new HashMap<Conditions, CondElementType>();
			rc32.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(60,80)));
			rc32.put(Conditions.DZONE, new IPv4Interval(10, 0, 26, new Interval(20,30)));
			rc32.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l3.add(new Rule("R2", RType.ALERTING, rc32, false));
			c3.setRules(l3);
			
			// C4
			List<Rule> l4 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc41 = new HashMap<Conditions, CondElementType>();
			rc41.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, 10));
			rc41.put(Conditions.DZONE, new IPv4Interval(10, 0, 25, BYTE));
			rc41.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l4.add(new Rule("R1", RType.ALERTING, rc41, true));
			Map<Conditions, CondElementType> rc42 = new HashMap<Conditions, CondElementType>();
			rc42.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, new Interval(60,80)));
			rc42.put(Conditions.DZONE, new IPv4Interval(10, 0, 25, BYTE));
			rc42.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l4.add(new Rule("R2", RType.ALERTING, rc42, true));
			Map<Conditions, CondElementType> rc43 = new HashMap<Conditions, CondElementType>();
			rc43.put(Conditions.SZONE, new IPv4Interval(192, 170, 22, new Interval(15,30)));
			rc43.put(Conditions.DZONE, new IPv4Interval(10, 0, 24, BYTE));
			rc43.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l4.add(new Rule("R3", RType.ALERTING, rc43, true));
			Map<Conditions, CondElementType> rc44 = new HashMap<Conditions, CondElementType>();
			rc44.put(Conditions.SZONE, new IPv4Interval(192, 170, 23, BYTE));
			rc44.put(Conditions.DZONE, new IPv4Interval(10, 0, 24, BYTE));
			rc44.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l4.add(new Rule("R4", RType.ALERTING, rc44, true));
			Map<Conditions, CondElementType> rc45 = new HashMap<Conditions, CondElementType>();
			rc45.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(18,20)));
			rc45.put(Conditions.DZONE, new IPv4Interval(10, 0, 27, BYTE));
			rc45.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l4.add(new Rule("R5", RType.ALERTING, rc45, true));
			c4.setRules(l4);

			// C5
			List<Rule> l5 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc51 = new HashMap<Conditions, CondElementType>();
			rc51.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, 10));
			rc51.put(Conditions.DZONE, new IPv4Interval(10, 0, 35, BYTE));
			rc51.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l5.add(new Rule("R1", RType.FILTERING, rc51, true));
			Map<Conditions, CondElementType> rc52 = new HashMap<Conditions, CondElementType>();
			rc52.put(Conditions.SZONE, new IPv4Interval(10, 0, 32, new Interval(60,80)));
			rc52.put(Conditions.DZONE, new IPv4Interval(10, 0, 35, BYTE));
			rc52.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l5.add(new Rule("R2", RType.FILTERING, rc52, true));
			Map<Conditions, CondElementType> rc53 = new HashMap<Conditions, CondElementType>();
			rc53.put(Conditions.SZONE, new IPv4Interval(192, 170, 22, new Interval(15,30)));
			rc53.put(Conditions.DZONE, new IPv4Interval(10, 0, 34, BYTE));
			rc53.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l5.add(new Rule("R3", RType.FILTERING, rc53, true));
			Map<Conditions, CondElementType> rc54 = new HashMap<Conditions, CondElementType>();
			rc54.put(Conditions.SZONE, new IPv4Interval(192, 170, 23, BYTE));
			rc54.put(Conditions.DZONE, new IPv4Interval(10, 0, 34, BYTE));
			rc54.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l5.add(new Rule("R4", RType.FILTERING, rc54, true));
			Map<Conditions, CondElementType> rc55 = new HashMap<Conditions, CondElementType>();
			rc55.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(18,20)));
			rc55.put(Conditions.DZONE, new IPv4Interval(10, 0, 36, BYTE));
			rc55.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l5.add(new Rule("R5", RType.FILTERING, rc55, true));
			c5.setRules(l5);
			
			// C6
			List<Rule> l6 = new ArrayList<Rule>();
			Map<Conditions, CondElementType> rc61 = new HashMap<Conditions, CondElementType>();
			rc61.put(Conditions.SZONE, new IPv4Interval(192, 170, 22, BYTE));
			rc61.put(Conditions.DZONE, new IPv4Interval(10, 0, 34, BYTE));
			rc61.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R1", RType.FILTERING, rc61, true));
			Map<Conditions, CondElementType> rc62 = new HashMap<Conditions, CondElementType>();
			rc62.put(Conditions.SZONE, new IPv4Interval(192, 170, 23, new Interval(18,20)));
			rc62.put(Conditions.DZONE, new IPv4Interval(10, 0, 34, BYTE));
			rc62.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R2", RType.FILTERING, rc62, true));
			Map<Conditions, CondElementType> rc63 = new HashMap<Conditions, CondElementType>();
			rc63.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(10,20)));
			rc63.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc63.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R3", RType.FILTERING, rc63, true));
			Map<Conditions, CondElementType> rc64 = new HashMap<Conditions, CondElementType>();
			rc64.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(21,70)));
			rc64.put(Conditions.DZONE, new IPv4Interval(200, 160, 1, BYTE));
			rc64.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R4", RType.FILTERING, rc64, true));
			Map<Conditions, CondElementType> rc65 = new HashMap<Conditions, CondElementType>();
			rc65.put(Conditions.SZONE, new IPv4Interval(192, 170, 22, BYTE));
			rc65.put(Conditions.DZONE, new IPv4Interval(10, 0, 24, BYTE));
			rc65.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R5", RType.FILTERING, rc65, true));
			Map<Conditions, CondElementType> rc66 = new HashMap<Conditions, CondElementType>();
			rc66.put(Conditions.SZONE, new IPv4Interval(192, 170, 23, new Interval(18,20)));
			rc66.put(Conditions.DZONE, new IPv4Interval(10, 0, 24, BYTE));
			rc66.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R6", RType.FILTERING, rc66, true));
			Map<Conditions, CondElementType> rc67 = new HashMap<Conditions, CondElementType>();
			rc67.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(10,23)));
			rc67.put(Conditions.DZONE, new IPv4Interval(10, 0, 26, BYTE));
			rc67.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R7", RType.FILTERING, rc67, true));
			Map<Conditions, CondElementType> rc68 = new HashMap<Conditions, CondElementType>();
			rc68.put(Conditions.SZONE, new IPv4Interval(192, 170, 21, new Interval(24,60)));
			rc68.put(Conditions.DZONE, new IPv4Interval(10, 0, 26, BYTE));
			rc68.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
			l6.add(new Rule("R8", RType.FILTERING, rc68, true));
			c6.setRules(l6);
			
		} catch (NetworkIntervalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IntervalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotInZoneException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IPAddressAlreadyUsedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return t;
	}
	
	@Test public void auditInterComponentFig4() {
		System.out.println("**** Test example 4 ****");
		Topology t = getTopoFig4();
		System.out.println("** Vérification audit intra **");
		int i = 0;
		for(Component c : t.getComponents()) {
			List<AuditWarning> warning = Algorithms.intraComponentAudit(c, c.getRules());
			i += warning.size();
			if(!warning.isEmpty()) System.out.println(AuditWarning.toString(warning));
		}
		if(i == 0) System.out.println("ok");
		System.out.println("** audit inter **");
		System.out.println(AuditWarning.toString(Algorithms.interComponentAudit(t)));
	}
	
}
