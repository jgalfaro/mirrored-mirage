package model;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import util.IPv4Interval;
import exception.IPAddressAlreadyUsedException;
import exception.NetworkIntervalException;


public class Zone {

	private final String name;
	private final Set<IPv4Interval> network;
	private final Map<IPv4Interval, Component> components;
	private final Set<Component> componentSet;
	private final Topology topology;
	private final Set<String> vulnerabilities;

	protected Zone(Topology topology, String name, IPv4Interval network) throws NetworkIntervalException {
		this.topology = topology;
		this.name = name;
		this.network = new HashSet<IPv4Interval>();
		this.network.add(network);
		this.components = new HashMap<IPv4Interval, Component>();
		this.componentSet = new HashSet<Component>();
		this.vulnerabilities = new HashSet<String>();
	}
	
	protected Zone(Topology topology, String name) throws NetworkIntervalException {
		this.topology = topology;
		this.name = name;
		this.network = new HashSet<IPv4Interval>();
		this.components = new HashMap<IPv4Interval, Component>();
		this.componentSet = new HashSet<Component>();
		this.vulnerabilities = new HashSet<String>();
	}
	
	public Topology getTopology() {
		return topology;
	}
	
	public String getName() {
		return name;
	}

	public Set<IPv4Interval> getNetwork() {
		return network;
	}

	public Set<Component> getComponents() {
		return componentSet;
	}

	public Set<String> getVulnerabilities() {
		return vulnerabilities;
	}
	
	public boolean isInZone(IPv4Interval ipaddress) {
		for(IPv4Interval i : network) {
			if(!i.inter(ipaddress).isEmpty()) return true;
		}
		return false;
	}
	
	public boolean isInterInZone(IPv4Interval ipaddress) {
		for(IPv4Interval i : network) {
			if(!i.inter(ipaddress).isEmpty()) return true;
		}
		return false;
	}

	
	public boolean contains(IPv4Interval ipaddress) {
		return components.containsKey(ipaddress);
	}
	
	protected void addComponent(IPv4Interval ipaddress, Component c) throws IPAddressAlreadyUsedException {
		if(!network.isEmpty() && !ipaddress.isEmpty()) {
			if(contains(ipaddress)) throw new IPAddressAlreadyUsedException(ipaddress, network);
			components.put(ipaddress, c);
		}
		componentSet.add(c);
	}

}
