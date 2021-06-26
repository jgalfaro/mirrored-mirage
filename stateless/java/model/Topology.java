package model;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import util.IPv4Interval;
import exception.IPAddressAlreadyUsedException;
import exception.NetworkIntervalException;

public class Topology {

	private final Map<String, Component> components;
	private final Map<String, Zone> zones;
	private final Map<Zone, Map<Zone, Set<Path>>> minimalRoutes;
	private boolean keepShortestRoutes = false;	// TODO voir si on conserve ou pas
	
	public Topology() {
		components = new HashMap<String, Component>();
		zones = new HashMap<String, Zone>();
		minimalRoutes = new HashMap<Zone, Map<Zone, Set<Path>>>();
	}
	
	public Zone getZone(String name) {
		return zones.get(name);
	}
	
	public Component getComponent(String name) {
		return components.get(name);
	}
	
	public Collection<Zone> getZones() {
		return zones.values();
	}
	
	public void setKeepShortestRoutes(boolean keepShortestRoutes) {
		this.keepShortestRoutes = keepShortestRoutes;
	}
	
	public Zone getZoneFromAddress(IPv4Interval ipaddress) {
		for(String name : zones.keySet()) {
			Zone z = zones.get(name);
			if(z.isInZone(ipaddress)) return z;
		}
		return null;
	}
	
	public Collection<Component> getComponents() {
		return components.values();
	}
	
	public Zone addZone(String name, IPv4Interval network) throws NetworkIntervalException {
		Zone zone = zones.get(name);
		if(zone == null) {
			zone = new Zone(this, name, network);
			zones.put(name, zone);
		}
		return zone;
	}
	
	public Zone addZone(String name) throws NetworkIntervalException {
		Zone zone = zones.get(name);
		if(zone == null) {
			zone = new Zone(this, name);
			zones.put(name, zone);
		}
		return zone;
	}

	
	public Component addComponent(String name, CType type, Set<NetworkInterface> networkInterfaces, boolean defaultPolicy) throws IPAddressAlreadyUsedException {
		Component component = components.get(name);
		if(component == null) {
			component = new Component(this, name, type, networkInterfaces, defaultPolicy);
			components.put(name, component);
		}
		return component;
	}
	
	public Component addComponent(String name, CType type, Set<NetworkInterface> networkInterfaces) throws IPAddressAlreadyUsedException {
		return addComponent(name, type, networkInterfaces, false);
	}
	
	public Set<Path> minimal_route(Zone z1, Zone z2) {
		Map<Zone, Set<Path>> m1 = minimalRoutes.get(z1);
		Set<Path> routes = null;
		if(m1 == null || (routes = m1.get(z2)) == null) {
			Map<Zone, Set<Path>> m2 = minimalRoutes.get(z2);
			Set<Component> starts = z1.getComponents();
			Set<Component> ends = z2.getComponents();
			routes = Collections.unmodifiableSet(minimal_route(z2, starts, ends));
			if(m1 == null) {
				m1 = new HashMap<Zone, Set<Path>>();
				minimalRoutes.put(z1, m1);
			}
			if(m2 == null) {
				m2 = new HashMap<Zone, Set<Path>>();
				minimalRoutes.put(z2, m2);
			}
			m1.put(z2, routes);
			Set<Path> reverse = new HashSet<Path>();
			for(Path p : routes) {
				reverse.add(p.reverse());
			}
			m2.put(z1, Collections.unmodifiableSet(reverse));
		}
		return routes;
	}
	
	private Set<Path> keepShortestRoutes(Set<Path> routes) {
		Set<Path> shortest = new HashSet<Path>();
		int min = Integer.MAX_VALUE;
		for(Path p : routes) {
			int size = p.getComponents().size(); 
			if(size < min) {
				shortest.clear();
				shortest.add(p);
				min = size;
			}
			else if(size == min) {
				min = size;
				shortest.add(p);
			}
		}
		return shortest;
	}
	
	private Set<Path> minimal_route(Zone Zend, Collection<Component> starts, Collection<Component> ends) {
		Set<Path> res = new HashSet<Path>();
		for(Component c : starts) {
			if(c.isAdjacent(Zend)) res.add(new Path(c));
			else find_path(new Path(c), res, starts, ends);
		}
		if(keepShortestRoutes) res = keepShortestRoutes(res);
		return res;
	}

	private void find_path(Path current, Set<Path> routes, Collection<Component> starts, Collection<Component> ends) {
		Component last = current.last();
		Iterator<Component> it = last.getConnected();
		while(it.hasNext()) {
			Component c = it.next();
			if(c.getType() == CType.UNKNOWN || starts.contains(c) || current.contains(c)) continue;
			Path p = current.add(c);
			if(ends.contains(c) && p.isMinimalRoute()) routes.add(p);
			else find_path(p, routes, starts, ends);   
		}
	}
	
}
