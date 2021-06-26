package main;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
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
import util.IPv4Interval;
import util.Interval;
import util.ProtocolSet;
import audit.Algorithms;
import audit.AuditWarning;
import exception.IntervalException;

public class MainTestRule {

	public static void main(String[] args) throws Exception {
		//test1();
		//test2();
		//test3();
		//test4();	// Redundancy
		testAuditIntra();
		//testExclusion();
		//testRandomRules(getComponentAndBuildTopo2(), 1000);
	}
	
	public static void test1() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(10, 40)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(20, 30)));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
		Rule B = new Rule("RB", RType.FILTERING, Bc, false);
		
		System.out.println("A = " + A);
		System.out.println("B = " + B);
	
		Rule C = Algorithms.exclusion(B, A);
		System.out.println("A exclus de B : " + C);
	}

	public static void test2() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(1, 50)));
		Rule B = new Rule("RB", RType.FILTERING, Bc, false);
		
		System.out.println("A = " + A);
		System.out.println("B = " + B);
	
		Rule C = Algorithms.exclusion(B, A);
		System.out.println("A exclus de B : " + C);
	}

	public static void test3() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(50, 60)));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
		Rule B = new Rule("RB", RType.FILTERING, Bc, false);
		
		System.out.println("A = " + A);
		System.out.println("B = " + B);
	
		Rule C = Algorithms.exclusion(B, A);
		System.out.println("A exclus de B : " + C);
		
		Map<Conditions, CondElementType> Dc = new HashMap<Conditions, CondElementType>();
		Dc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
		Dc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 40)));
		Rule D = new Rule("RD", RType.FILTERING, Dc, false);
		
		System.out.println("D = " + D);
		Rule E = Algorithms.exclusion(C, D);
		System.out.println("D exclus de (A exclus de B) : " + E);

		System.out.println("C = " + C);
		Rule F = Algorithms.exclusion(E, C);
		System.out.println("(A exclus de B) exclus de (D exclus de (A exclus de B)) : " + F);
		
	}

	public static void test4() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(50, 60)));
		Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
		Bc.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule B = new Rule("RB", RType.FILTERING, Bc, true);
		
		Map<Conditions, CondElementType> Dc = new HashMap<Conditions, CondElementType>();
		Dc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));
		Dc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 40)));
		Dc.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule D = new Rule("RD", RType.FILTERING, Dc, true);
	
		List<Rule> R = new LinkedList<Rule>();
		R.add(A);R.add(B);R.add(D);
		List<Rule> RR = new LinkedList<Rule>(R);
		
		for(Rule r : R) {
			RR.remove(r);
			System.out.println("Redondance de " + r.getCondition() + "\n" + Algorithms.testRedundancy(RR, r));
		}
	}
	
	public static Component getComponentAndBuildTopo() throws Exception {
		Topology t = new Topology();
		Zone external = t.addZone("network1",  
				new IPv4Interval(192,168,120, new Interval(0, 50)));
		Zone DMZ = t.addZone("DMZ", 
				new IPv4Interval(192,168,120, new Interval(51, 100)));
		Zone private1 = t.addZone("private1", 
				new IPv4Interval(192,168,120, new Interval(101, 150)));
		Zone private2 = t.addZone("private2", 
				new IPv4Interval(192,168,120, new Interval(151, 200)));
		Zone private3 = t.addZone("private3", 
				new IPv4Interval(192,168,120, new Interval(201, 255)));
		
		Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
		s1.add(new NetworkInterface(new IPv4Interval(192,168,120,1), external));
		s1.add(new NetworkInterface(new IPv4Interval(192,168,120,55), DMZ));
		Component c = t.addComponent("FW1", CType.FIREWALL, s1);
		
		return c;
	}
	
	public static Component getComponentAndBuildTopo2() throws Exception {
		Topology t = new Topology();
		Zone external = t.addZone("network1",  
				new IPv4Interval(192,168,120, new Interval(0, 255)));
		Zone DMZ = t.addZone("DMZ", 
				new IPv4Interval(192,168,121, new Interval(0, 255)));
		Zone private1 = t.addZone("private1", 
				new IPv4Interval(192,168,122, new Interval(0, 255)));
		Zone private2 = t.addZone("private2", 
				new IPv4Interval(192,168,123, new Interval(0, 255)));
		Zone private3 = t.addZone("private3", 
				new IPv4Interval(192,168,124, new Interval(0, 255)));
		
		Set<NetworkInterface> s1 = new HashSet<NetworkInterface>();
		s1.add(new NetworkInterface(new IPv4Interval(192,168,120,1), external));
		s1.add(new NetworkInterface(new IPv4Interval(192,168,121,55), DMZ));
		Component c = t.addComponent("FW1", CType.FIREWALL, s1);
		
		return c;
	}

	
	public static void testAuditIntra() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(101, 150)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(30, 40)));
		Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(101, 150)));
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 50)));
		Bc.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule B = new Rule("RB", RType.FILTERING, Bc, true);
		
		Map<Conditions, CondElementType> Dc = new HashMap<Conditions, CondElementType>();
		Dc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(101, 150)));
		Dc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 35)));
		Dc.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule D = new Rule("RD", RType.FILTERING, Dc, true);

		Map<Conditions, CondElementType> Ec = new HashMap<Conditions, CondElementType>();
		Ec.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(101, 150)));		
		Ec.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(30, 45)));
		Ec.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule E = new Rule("RE", RType.FILTERING, Ec, false);
		
		Map<Conditions, CondElementType> Fc = new HashMap<Conditions, CondElementType>();
		Fc.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(101, 150)));		
		Fc.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(123, 140)));
		//Fc.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule F = new Rule("RF", RType.FILTERING, Fc, false);
		
		Component c = getComponentAndBuildTopo();
		List<Rule> R = new LinkedList<Rule>();
		R.add(A);
		R.add(B);
		R.add(D);
		R.add(E);
		R.add(F);
		c.setRules(R);
		
		System.out.println("**** Before Audit ****");
		System.out.println(c.getRules());
		
		System.out.println("**** Audit ****");
		System.out.println(AuditWarning.toString(Algorithms.intraComponentAudit(c, c.getRules())));
		
		System.out.println("**** After Audit ****");
		System.out.println(c.getRules());
		
	}
	
	public static void testExclusion() throws Exception {
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(0, 70)));
		Ac.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule A = new Rule("RA", RType.FILTERING, Ac, true);
	
		Map<Conditions, CondElementType> Ec = new HashMap<Conditions, CondElementType>();
		Ec.put(Conditions.SZONE, new IPv4Interval(192, 168, 120, new Interval(1, 60)));		
		Ec.put(Conditions.DZONE, new IPv4Interval(192, 168, 120, new Interval(50, 65)));
		//Ec.put(Conditions.PROTOCOL, new ProtocolSet("tcp"));
		Rule E = new Rule("RE", RType.FILTERING, Ec, false);
		
		System.out.println("Ri : " + A);
		System.out.println("Rj : " + E);
		Rule r = Algorithms.exclusion(E, A);
		System.out.println("Exclusion : " + r);
	}

	public static void setRandomRules(Component c, int maxR) throws Exception {
		Topology t = c.getTopology();
		List<Rule> rules = new ArrayList<Rule>();
		for(int i = 0; i < maxR; i++) {
			Map<Conditions, CondElementType> cond = new HashMap<Conditions, CondElementType>();
			boolean b = Math.round(Math.random()) == 1 ? true : false;
			cond.put(Conditions.SZONE, getRandomIPv4Interval(t));
			cond.put(Conditions.DZONE, getRandomIPv4Interval(t));
			//cond.put(Conditions.DPORT, getRandomInterval());
			int v = (int) (Math.round(Math.random()) * 3);
			String protocol = v == 0 ? "tcp" : v == 1 ? "udp" : null;
			//cond.put(Conditions.PROTOCOL, new ProtocolSet(protocol));
			rules.add(new Rule("R" + (i+1), RType.FILTERING, cond, b));
		}
		c.setRules(rules);
	}
	
	public static void testRandomRules(Component c, int maxR) throws Exception {
		setRandomRules(c, maxR);
		
		System.out.println("**** Audit ****");
		Date startTimeReq = new Date();
		List<AuditWarning> warn = Algorithms.intraComponentAudit(c, c.getRules());
		Date endTimeReq = new Date();
		AuditWarning.toString(warn);
		System.out.println("Audit finished after " + (endTimeReq.getTime() - startTimeReq.getTime()) + "ms");
		
		List<Rule> res = Rule.cleanRules(c.getRules(), c.getDefaultPolicy());
		/*for(Rule r : res) {
			System.out.println(r.getCondition());
		}*/
		System.out.println("Total final règles : " + res.size());
		
	}
	
	public static void setAuditDebug(Component c) throws Exception {
		boolean b = c.getDefaultPolicy();
		Map<Conditions, CondElementType> Ac = new HashMap<Conditions, CondElementType>();
		Ac.put(Conditions.SZONE, new IPv4Interval(192, 168, 130, new Interval(36, 140)));		
		Ac.put(Conditions.DZONE, new IPv4Interval(192, 168, 125, new Interval(35, 135)));
		Rule A = new Rule("R11", RType.FILTERING, Ac, !b);
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 130, new Interval(15, 243)));		
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 125, new Interval(88, 160)));
		Rule B = new Rule("R26", RType.FILTERING, Bc, !b);

		Map<Conditions, CondElementType> Cc = new HashMap<Conditions, CondElementType>();
		Cc.put(Conditions.SZONE, new IPv4Interval(192, 168, 130, new Interval(39, 136)));		
		Cc.put(Conditions.DZONE, new IPv4Interval(192, 168, 125, new Interval(135, 179)));
		Rule C = new Rule("R28", RType.FILTERING, Cc, !b);

		List<Rule> rules = new ArrayList<Rule>();
		rules.add(A);rules.add(B);rules.add(C);
		c.setRules(rules);
		
		System.out.println(Algorithms.exclusion(Algorithms.exclusion(C, A), B));
		
	}
	
	public static void setAuditDebug2(Component c) throws Exception {
		boolean b = c.getDefaultPolicy();
		
		Map<Conditions, CondElementType> Bc = new HashMap<Conditions, CondElementType>();
		//Bc.put(Conditions.SZONE, new IPv4Interval(192, 168, 130, new Interval(36, 140)));		
		Bc.put(Conditions.DZONE, new IPv4Interval(192, 168, 125, new Interval(135, 160)));
		Rule B = new Rule("R26", RType.FILTERING, Bc, !b);

		Map<Conditions, CondElementType> Cc = new HashMap<Conditions, CondElementType>();
		//Cc.put(Conditions.SZONE, new IPv4Interval(192, 168, 130, new Interval(39, 136)));		
		Cc.put(Conditions.DZONE, new IPv4Interval(192, 168, 125, new Interval(136, 159)));
		Rule C = new Rule("R28", RType.FILTERING, Cc, !b);

		List<Rule> rules = new ArrayList<Rule>();
		rules.add(B);rules.add(C);
		c.setRules(rules);
		
		System.out.println(Algorithms.exclusion(C, B));
		
	}
	
	public static IPv4Interval getRandomIPv4Interval(Topology t) throws IntervalException {
		List<Zone> zones  = new ArrayList<Zone>(t.getZones());
		Zone z1 = zones.get((int) Math.round(Math.random() * (zones.size() - 1)));
		IPv4Interval network1 = z1.getNetwork().iterator().next(); 
		Interval interval = network1.getD();
		int v1 = interval.getBegin() + (int) Math.round(Math.random() * interval.getEnd());
		int v2 = interval.getBegin() + (int) Math.round(Math.random() * interval.getEnd());
		//int v2 = (v1 + 10) % 255;
		if(v1 > v2) {
			int tmp = v1;v1 = v2;v2 = tmp;
		}
		return new IPv4Interval(network1.getA(), 
				network1.getB(), 
				network1.getC(), 
				new Interval(v1, v2));
	}
	
	public static Interval getRandomInterval() throws IntervalException {
		int v1 = (int) Math.round(Math.random() * 65635);
		int v2 = (int) Math.round(Math.random() * 65635);
		if(v1 > v2) {
			int tmp = v1;v1 = v2;v2 = tmp;
		}
		return new Interval(v1, v2);
		
	}
	
}
