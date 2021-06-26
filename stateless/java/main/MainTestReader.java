package main;

import java.util.Iterator;

import io.SkyboxReader;
import io.Reader;
import model.CType;
import model.Component;
import model.NetworkInterface;
import model.Rule;
import model.Topology;
import model.Zone;
import audit.Algorithms;
import audit.Audit;
import audit.AuditWarning;

public class MainTestReader {

	public static void main(String[] args) throws Exception {
		test1();
		test2();
		test3();
		test4();
	}

	public static void test1() throws Exception {
		SkyboxReader sr = new SkyboxReader("../xml-examples/20100206-sec1Net-intra-anom_inter_anom.xml");
		Topology t = sr.getTopology();
		t.setKeepShortestRoutes(true);
		for(Zone z : t.getZones()) {
			System.out.println(z.getName() + ":" + z.getNetwork());
		}
		System.out.println();
		for(Component c : t.getComponents()) {
			System.out.println("** " + c.getName() + " : " + c.getDefaultPolicy() +" **");
			System.out.println(c.getRules());
		}
		Audit audit = new Audit(t);
		System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
	}

	public static void test2() throws Exception {
            //SkyboxReader sr = new SkyboxReader("../xml-examples/20100206-sec1Net_inter_anom.xml");
            SkyboxReader sr = new SkyboxReader("./test2.xml");
            Topology t = sr.getTopology();
            t.setKeepShortestRoutes(true);
            for(Zone z : t.getZones()) {
                System.out.println(z.getName() + ":" + z.getNetwork());
            }
            System.out.println();
            for(Component c : t.getComponents()) {
                System.out.println("** " + c.getName() + " : " + c.getDefaultPolicy() +" **");
                System.out.println(c.getRules());
            }
            Audit audit = new Audit(t);
            System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
            Algorithms.cleanAll(t);
            System.out.println(AuditWarning.toString(audit.interComponentAudit()));
	}

	public static void test3() throws Exception {
		SkyboxReader sr = new SkyboxReader("../xml-examples/sampleSkyboxNetwork.xml");
		Topology t = sr.getTopology();
		System.out.println("Components : " + t.getComponents().size());
		System.out.println("Zones : " + t.getComponents().size());
		t.setKeepShortestRoutes(false);
		for(Zone z : t.getZones()) {
			System.out.println(z.getName() + ":" + z.getNetwork() + ":" + z.getComponents());
		}
		System.out.println();
		for(Component c : t.getComponents()) {
			if(c.getType() == CType.FIREWALL || c.getType() == CType.NIDS) {
				System.out.println("** " + c.getName() + " : " + c.getDefaultPolicy() +" **");
				System.out.println(c.getRules());
			}
		}
		Audit audit = new Audit(t);
		System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
		Algorithms.cleanAll(t);
		System.out.println(AuditWarning.toString(audit.interComponentAudit()));
		System.out.println(audit.aggregation());
	}

	public static void test4() throws Exception {
		Reader sr = new Reader("../test.xml");
		Topology t = sr.getTopology();
		System.out.println("Components : " + t.getComponents().size());
		System.out.println("Zones : " + t.getZones().size());
		System.out.println("C6 adjacent à E2 ? " + t.getComponent("C6").isAdjacent(t.getZone("E2")));
		t.setKeepShortestRoutes(false);
		for(Zone z : t.getZones()) {
			System.out.println(z.getName() + ":" + z.getNetwork() + ":" + z.getComponents());
		}
		System.out.println();
		for(Component c : t.getComponents()) {
			if(c.getType() == CType.FIREWALL || c.getType() == CType.NIDS) {
				System.out.println("** " + c.getName() + " : " + c.getDefaultPolicy() +" **");
				System.out.println(c.getRules());
			}
		}
		Audit audit = new Audit(t);
		System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
		Algorithms.cleanAll(t);
		System.out.println(AuditWarning.toString(audit.interComponentAudit()));
		System.out.println(audit.aggregation());
	}

	private static void test() throws Exception {
		Reader sr = new Reader("./test.xml");
		Topology t = sr.getTopology();
		printTopology(t);
	}

	protected static void printTopology(Topology t) {
		printTopology(t, false);
	}

	protected static void printTopology(Topology t, boolean details) {
		System.out.println("Components : " + t.getComponents().size());
		System.out.println("Zones : " + t.getZones().size());
		for(Zone z : t.getZones()) {
			System.out.println(z.getName() + " : " + z.getNetwork());
		}
		for(Component c : t.getComponents()) {
			System.out.println("**** " + c.getName() + " ****");
			System.out.println("Type : " + c.getType());
			System.out.println("Rules : " + c.getRules().size());
			if(details) {
				for(Rule r : c.getRules()) {
					System.out.println(r);
				}
			}
			for(NetworkInterface n : c.getNetworkInterfaces()) {
				System.out.print(n.getZone().getName() + " | ");
			}
			Iterator<Component> it = c.getConnected();
			System.out.println();
			while(it.hasNext()) System.out.print(it.next() + " | ");
			System.out.println();
		}
	}

}
