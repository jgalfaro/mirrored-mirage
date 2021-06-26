package model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import exception.IPAddressAlreadyUsedException;


public class Component {

	private final Topology topology;
	private final String name;
	private final CType type;

	private final Set<NetworkInterface> networkInterfaces;
	private final Set<Zone> zones;				// Adjacent zones
	private final Set<Component> components;	// Connected components
	private List<Rule> rules;
	private boolean defaultPolicy;
	
	protected Component(Topology topology, String name, CType type, Set<NetworkInterface> networkInterfaces, boolean defaultPolicy) throws IPAddressAlreadyUsedException {
		this.topology = topology;
		this.name = name;
		this.type = type;
		this.networkInterfaces = Collections.unmodifiableSet(networkInterfaces);
		this.defaultPolicy = defaultPolicy;
		this.components = new HashSet<Component>();
		this.rules = new ArrayList<Rule>();
		this.zones = new HashSet<Zone>();
		for(NetworkInterface i : this.networkInterfaces) {
			Zone z = i.getZone();
			for(Component c : z.getComponents()) {
				components.add(c);
				c.addConnected(this);
			}
			zones.add(z);
			z.addComponent(i.getIPAddress(), this);
		}
	}
	
	public boolean isAdjacent(Zone z) {
		return zones.contains(z);
	}

	public boolean isConnected(Component c) {
		return components.contains(c);
	}

	public Set<NetworkInterface> getNetworkInterfaces() {
		return networkInterfaces;
	}

	public CType getType() {
		return type;
	}
	
	public String getName() {
		return name;
	}
	
	public void setDefaultPolicy(boolean defaultPolicy) {
		this.defaultPolicy = defaultPolicy;
	}
	
	public boolean getDefaultPolicy() {
		return defaultPolicy;
	}
	
	public Topology getTopology() {
		return topology;
	}
	
	public List<Rule> getRules() {
		return rules;
	}
	
	public void setRules(List<Rule> rules) {
		this.rules = rules;
	}

	public Iterator<Component> getConnected() {
		return components.iterator();
	}
	
	protected void addConnected(Component c) {
		components.add(c);
	}
	
	@Override
	public String toString() {
		return "Component:" + name;
	}
	
}
