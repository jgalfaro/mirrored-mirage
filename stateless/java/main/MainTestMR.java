package main;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import model.CType;
import model.Component;
import model.NetworkInterface;
import model.Rule;
import model.Topology;
import model.Zone;
import util.IPv4Interval;
import util.Interval;
import audit.Algorithms;
import audit.AuditWarning;

public class MainTestMR {

	
	public static void main(String[] args) throws Exception {
		Topology t = buildTopo1();
		//test0(t);
		testIntra(t, 100);	// testIntra avec 100 règles générées
		Algorithms.cleanAll(t);
		testIntra(t);	// testIntra
		testInter(t);
		//testAlgo10(t, 100);
	}
	
	public static void test0(Topology t) throws Exception {
		Date startTimeReq = new Date();
		testMR1(t);
		Date endTimeReq = new Date();
		System.out.println("finished after " + (endTimeReq.getTime() - startTimeReq.getTime()) + "ms");
		startTimeReq = new Date();
		testMR1(t);
		endTimeReq = new Date();
		System.out.println("finished after " + (endTimeReq.getTime() - startTimeReq.getTime()) + "ms");
	}
	
	public static void testIntra(Topology t, int maxR) throws Exception {
		MainTestRule.setRandomRules(t.getComponent("FW1"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW2"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW3"), maxR);
		//TestRule.setAuditDebug(t.getComponent("FW3"));
		MainTestRule.setRandomRules(t.getComponent("FW4"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW5"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW6"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW7"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW8"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW9"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW10"), maxR);
		//for(Rule r : t.getComponent("FW3").getRules()) System.out.println("FW3{"+r.getName()+"}:"+r.getCondition());
		testIntra(t);
	}
	
	public static void testIntra(Topology t) throws Exception {
		Date startTimeReq = new Date();
		auditIntra(t.getComponent("FW1"));
		auditIntra(t.getComponent("FW2"));
		auditIntra(t.getComponent("FW3"));
		auditIntra(t.getComponent("FW4"));
		auditIntra(t.getComponent("FW5"));
		auditIntra(t.getComponent("FW6"));
		auditIntra(t.getComponent("FW7"));
		auditIntra(t.getComponent("FW8"));
		auditIntra(t.getComponent("FW9"));
		auditIntra(t.getComponent("FW10"));
		Date endTimeReq = new Date();
		System.out.println("Total audit finished after " + (endTimeReq.getTime() - startTimeReq.getTime()) + "ms");
	}
	
	public static void auditIntra(Component c) {
		System.out.println("**** Audit ****");
		Date startTimeReq = new Date();
		List<AuditWarning> warn = Algorithms.intraComponentAudit(c, c.getRules());
		Date endTimeReq = new Date();
		System.out.println(AuditWarning.toString(warn));
		System.out.println("Audit finished after " + (endTimeReq.getTime() - startTimeReq.getTime()) + "ms");
		
		List<Rule> res = Rule.cleanRules(c.getRules(), c.getDefaultPolicy());
		/*for(Rule r : res) {
			System.out.println(r.getCondition());
		}*/
		System.out.println("Total final règles : " + res.size());
	}
	
	public static Topology buildTopo1() throws Exception {
		Topology t = new Topology();
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
		
		return t;
	}
	
	public static void testMR1(Topology t) throws Exception {
		List<Zone> zones = new ArrayList<Zone>(t.getZones());
		for(int i = 0; i < zones.size() - 1; i++) {
			Zone z1 = zones.get(i);
			for(int j = i + 1; j < zones.size(); j++) {
				Zone z2 = zones.get(j);
				System.out.println(z1.getName() + "->" + z2.getName() + " : " + t.minimal_route(z1, z2));
			}
		}
		for(int i = zones.size() - 1; i >= 0; i--) {
			Zone z1 = zones.get(i);
			for(int j = i - 1; j >= 0; j--) {
				Zone z2 = zones.get(j);
				System.out.println(z1.getName() + "->" + z2.getName() + " : " + t.minimal_route(z1, z2));
			}
		}
	}

	public static void testInter(Topology t) {
		System.out.println("**** Test inter component audit ****");
		System.out.println(AuditWarning.toString(Algorithms.interComponentAudit(t)));
	}

	public static void testAlgo10(Topology t, int maxR) throws Exception {
		MainTestRule.setRandomRules(t.getComponent("FW1"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW2"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW3"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW4"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW5"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW6"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW7"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW8"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW9"), maxR);
		MainTestRule.setRandomRules(t.getComponent("FW10"), maxR);
		List<Rule> R = Algorithms.aggregation(t);
		System.out.println("*** Résultat aggrégation ***");
		for(Rule r : R) {
			if(!r.getCondition().isEmpty()) {
				System.out.println(r.getName() + ":" + r.getCondition());
			}
		}

	}
	
}
