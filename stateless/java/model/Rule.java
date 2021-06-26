package model;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import util.IPv4Interval;

public class Rule {

	private Set<Map<Conditions, CondElementType>> condition;
	private Map<Conditions, CondElementType> origCondition;
	private boolean decision;
	private RType type;
	private boolean shadowing;
	private boolean redundancy;
	private boolean irrelevance;
	private final List<Rule> exclusionList;
	private final String name;
	
	public Rule(String name, RType type, Map<Conditions, CondElementType> condition, boolean decision) {
		this.name = name;
		this.type = type;
		this.condition = new HashSet<Map<Conditions,CondElementType>>();
		this.origCondition = condition;
		this.condition.add(condition);
		this.decision = decision;
		this.shadowing = false;
		this.redundancy = false;
		this.irrelevance = false;
		this.exclusionList = new LinkedList<Rule>();
	}

	public Set<Map<Conditions, CondElementType>> getCondition() {
		return condition;
	}
	
	public Map<Conditions, CondElementType> getOrigCondition() {
		return origCondition;
	}
	
	public boolean getDecision() {
		return decision;
	}
	
	public String getName() {
		return name;
	}
	
	public RType getType() {
		return type;
	}
	
	public boolean isShadowing() {
		return shadowing;
	}
	
	public boolean isRedundancy() {
		return redundancy;
	}
	
	public boolean isIrrelevance() {
		return irrelevance;
	}
	
	public void setShadowing(boolean shadowing) {
		this.shadowing = shadowing;
	}
	
	public void setRedundancy(boolean redundancy) {
		this.redundancy = redundancy;
	}
	
	public void setIrrelevance(boolean irrelevance) {
		this.irrelevance = irrelevance;
	}

	public List<Rule> getExclusionList() {
		return exclusionList;
	}
	
	public void addExclusionList(Rule r) {
		exclusionList.add(r);
	}
	
	public String printExclusionList() {
		String res = "{}";
		res = printList(exclusionList.iterator());
		return res;
	}
	
	public static String printList(Iterator<Rule> it) {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		PrintWriter p = new PrintWriter(bout);
		p.print("{");
		if(it.hasNext()) {
			p.print(it.next().getName());
			while(it.hasNext()) {
				p.print("," + it.next().getName());
			}
		}
		p.print("}");
		p.flush();
		return bout.toString();
	}
	
	public IPv4Interval getDzone() {
		if(!condition.isEmpty()) {
			return (IPv4Interval) condition.iterator().next().get(Conditions.DZONE);
		}
		return (IPv4Interval) IPv4Interval.EMPTY.getDefaultAny();
	}
	
	public IPv4Interval getSzone() {
		if(!condition.isEmpty()) {
			return (IPv4Interval) condition.iterator().next().get(Conditions.SZONE);
		}
		return (IPv4Interval) IPv4Interval.EMPTY.getDefaultAny();
	}
	
	public void replaceWith(Rule r) {
		this.condition = r.getCondition();
	}
	
	/**
	 * Clean rule list by removing empty rules (for instance because of shadowing after audit)
	 * Split in several rules if a rule has several subconditions
	 * @param rules
	 * @param defaultPolicy
	 * @return
	 */
	public static List<Rule> cleanRules(List<Rule> rules, boolean defaultPolicy) {
		List<Rule> res = new ArrayList<Rule>();
		for(Rule r : rules) {
			if(!(defaultPolicy == r.getDecision() || r.getCondition().isEmpty())) {
				int i = 0;
				// Only 1 condition
				if(r.getCondition().size() == 1) {
					res.add(new Rule(r.getName(), r.getType(), 
							r.getCondition().iterator().next(),
							r.getDecision()));
				}
				else {	// Split the conditions in different rules
					for(Map<Conditions, CondElementType> cond : r.getCondition()) {
						i++;
						res.add(new Rule(r.getName() + "." + i, r.getType(), cond, r.getDecision()));
					}
				}
			}
		}
		return res;
	}
	
	@Override
	public String toString() {
		String res = "";
		res += "Name:" + name;
		res += "\nType:" + type + "(" + decision + ")";
		res += "\nCondition:" + condition;
		return res;
	}
	
}
