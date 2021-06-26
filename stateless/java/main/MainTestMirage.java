package main;

import java.util.HashSet;
import java.util.Set;

import util.IPv4Interval;
import util.Interval;

import model.CType;
import model.Component;
import model.NetworkInterface;
import model.Path;
import model.Topology;
import model.Zone;

public class MainTestMirage {

	public static void main(String[] args) throws Exception {
		test1();
	}
	
	private static void test1() throws Exception {
		Topology t = new Topology();
		Zone external = t.addZone("external network",  
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
		Component C1 = t.addComponent("C1", CType.FIREWALL, s1);
		
		Set<NetworkInterface> s2 = new HashSet<NetworkInterface>();
		s2.add(new NetworkInterface(new IPv4Interval(192,168,120,111), private1));
		s2.add(new NetworkInterface(new IPv4Interval(192,168,120,60), DMZ));
		Component C2 = t.addComponent("C2", CType.FIREWALL, s2);

		Set<NetworkInterface> s3 = new HashSet<NetworkInterface>();
		s3.add(new NetworkInterface(new IPv4Interval(192,168,120,151), private2));
		s3.add(new NetworkInterface(new IPv4Interval(192,168,120,70), DMZ));
		Component C3 = t.addComponent("C3", CType.FIREWALL, s3);

		Set<NetworkInterface> s4 = new HashSet<NetworkInterface>();
		s4.add(new NetworkInterface(new IPv4Interval(192,168,120,205), private3));
		s4.add(new NetworkInterface(new IPv4Interval(192,168,120,113), private1));
		Component C4 = t.addComponent("C4", CType.FIREWALL, s4);

		System.out.println(t.getComponents());
		
		System.out.println("C1 connected C2 : " + C1.isConnected(C2) + " " + C2.isConnected(C1));
		System.out.println("C1 connected C3 : " + C1.isConnected(C3) + " " + C3.isConnected(C1));
		System.out.println("C1 connected C4 : " + C1.isConnected(C4) + " " + C4.isConnected(C1));
		System.out.println("C2 connected C3 : " + C2.isConnected(C3) + " " + C3.isConnected(C2));
		System.out.println("C2 connected C4 : " + C2.isConnected(C4) + " " + C4.isConnected(C2));
		System.out.println("C3 connected C4 : " + C3.isConnected(C4) + " " + C4.isConnected(C3));
		
		System.out.println("C1 adjacent external : " + C1.isAdjacent(external));
		System.out.println("C1 adjacent DMZ : " + C1.isAdjacent(DMZ));
		System.out.println("C1 adjacent private1 : " + C1.isAdjacent(private1));
		System.out.println("C1 adjacent private2 : " + C1.isAdjacent(private2));
		System.out.println("C1 adjacent private3 : " + C1.isAdjacent(private3));
		
		System.out.println("C2 adjacent external : " + C2.isAdjacent(external));
		System.out.println("C2 adjacent DMZ : " + C2.isAdjacent(DMZ));
		System.out.println("C2 adjacent private1 : " + C2.isAdjacent(private1));
		System.out.println("C2 adjacent private2 : " + C2.isAdjacent(private2));
		System.out.println("C2 adjacent private3 : " + C2.isAdjacent(private3));

		System.out.println("C3 adjacent external : " + C3.isAdjacent(external));
		System.out.println("C3 adjacent DMZ : " + C3.isAdjacent(DMZ));
		System.out.println("C3 adjacent private1 : " + C3.isAdjacent(private1));
		System.out.println("C3 adjacent private2 : " + C3.isAdjacent(private2));
		System.out.println("C3 adjacent private3 : " + C3.isAdjacent(private3));

		System.out.println("C4 adjacent external : " + C4.isAdjacent(external));
		System.out.println("C4 adjacent DMZ : " + C4.isAdjacent(DMZ));
		System.out.println("C4 adjacent private1 : " + C4.isAdjacent(private1));
		System.out.println("C4 adjacent private2 : " + C4.isAdjacent(private2));
		System.out.println("C4 adjacent private3 : " + C4.isAdjacent(private3));

		
		Path p1 = new Path(C1).add(C2).add(C4);
		System.out.println(p1.route(external, private3));
		System.out.println(p1.route(external, private2));
		System.out.println("MR C1;C2;C4 : " + p1.isMinimalRoute());
		
		Path p2 = new Path(C1).add(C3).add(C2).add(C4);
		System.out.println(p2.route(external, private3));
		System.out.println(p2.route(external, private2));
		System.out.println("MR C1;C3;C2;C4 : " + p2.isMinimalRoute());

	}
	
}
