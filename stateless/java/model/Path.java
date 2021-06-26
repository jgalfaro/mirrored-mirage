package model;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class Path {

	private final List<Component> components; 

	public Path(Component component) {
		List<Component> l = new ArrayList<Component>();
		l.add(component);
		this.components = Collections.unmodifiableList(l);
	}
	
	public Path(List<Component> components) {
		this.components = Collections.unmodifiableList(components);
	}
	
	public Path add(Component component) {
		if(components.contains(component) || !last().isConnected(component)) return null;
		else {
			List<Component> l = new ArrayList<Component>(this.components);
			l.add(component);
			return new Path(l);
		}
	}
	
	public Path reverse() {
		List<Component> l = new ArrayList<Component>();
		for(int i = components.size() - 1; i >= 0; i--) {
			l.add(components.get(i));
		}
		return new Path(l);
	}
	
	public boolean contains(Component c) {
		return components.contains(c);
	}
	
	public List<Component> getComponents() {
		return components;
	}
	
	public int length() {
		return components.size();
	}
	
	public Component first() {
		return components.get(0);
	}

	public Component last() {
		return components.get(components.size() -1);
	}
	
	/**
	 * 
	 * @param c This component is inside this path 
	 * @return
	 */
	public Path head(Component c) {
		List<Component> l = new ArrayList<Component>();
		if(components.contains(c)) {
			for(Component comp : components) {
				if(comp.equals(c)) break;
				l.add(comp);
			}
		}
		return new Path(l);		
	}
	
	/**
	 * 
	 * @param c This component is inside this path
	 * @return
	 */
	public Path tail(Component c) {
		List<Component> l = new ArrayList<Component>();
		boolean go = false;
		for(Component comp : components) {
			if(comp.equals(c)) go = true;
			else if(go) l.add(comp);
		}
		return new Path(l);		
	}

	public boolean isMinimalRoute() {
		return isMinimalRoute(0);
	}
	
	private boolean isMinimalRoute(int i) {
		if(i == (components.size() - 1)) return true;	// [c] is a minimal route
		Component c1 = components.get(i);
		if(i == (components.size() - 2)) return true;		// [c1,c2] minimal route
		for(int j = i + 2; j < components.size(); j++) {
			if(c1.isConnected(components.get(j))) return false;	// shortcut [c1, cj,..,cn] ; j > 2
		}
		return isMinimalRoute(i + 1);
	}

	public boolean route(Zone z1, Zone z2) {
		return first().isAdjacent(z1) && last().isAdjacent(z2);
	}
	
	public boolean isEmpty() {
		return components.isEmpty();
	}

	@Override
	public String toString() {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrintWriter p = new PrintWriter(out);
		p.print("[");
		if(!components.isEmpty()) {
			p.print(first().getName());
			for(int i = 1; i < components.size(); i++) {
				p.print(":");
				p.print(components.get(i).getName());
			}
		}
		p.print("]");
		p.flush();
		return out.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if(obj instanceof Path) {
			Path p = (Path) obj;
			return components.equals(p.components);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return components.hashCode();
	}
	
}
