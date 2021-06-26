package audit;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import model.CType;
import model.Component;
import model.CondElementType;
import model.Conditions;
import model.Path;
import model.Rule;
import model.Topology;
import model.Zone;
import util.IPv4Interval;
import util.StringField;
import exception.IncompatibleElementType;

public class Algorithms {

	public static String crName(Component c, Rule r) {
		return c.getName() + "{" + r.getName() + "}";
	}
	
	public static String crName(Component c, Iterator<Rule> it) {
		return c.getName() + Rule.printList(it);
	}

	
	/**
	 *               Begin Algorithm 1               
	 ************************************************/
	
	/**
	 * Algorithm 1 
	 * @param A
	 * @param B
	 * @return
	 */
	public static Rule exclusion(Rule B, Rule A) {
		Rule C = new Rule(B.getName(), B.getType(), B.getOrigCondition(), B.getDecision());
		C.replaceWith(B);
		boolean exclusion = false;
		for(Map<Conditions, CondElementType> Ac : A.getCondition()) {
			Rule r = exclusion2(C, new Rule(A.getName(), A.getType(), Ac, A.getDecision()));
			if(r != C) {
				exclusion = true;
				C.replaceWith(r);
			}
		}
		return exclusion ? C : B;
	}
	
	/**
	 * exclusion A from B, with A condition set is a singleton
	 * @param B
	 * @param A
	 * @return
	 */
	private static Rule exclusion2(Rule B, Rule A) {
		Rule C = new Rule(B.getName(), B.getType(), B.getOrigCondition(), B.getDecision());
		Conditions[] Ctypes = Conditions.values();
		Set<Map<Conditions, CondElementType>> exclusionCondition = new HashSet<Map<Conditions,CondElementType>>();
		Map<Conditions, CondElementType> Ac = A.getOrigCondition();
		boolean exclusion = false;
		for(Map<Conditions, CondElementType> Bc : B.getCondition()) {
			Map<Conditions, CondElementType> AinterB = new HashMap<Conditions, CondElementType>();
			if(checkAllInterNotEmpty(AinterB, Ctypes, Ac, Bc)) {
				exclusion = true;
				exclusionCondition.addAll(getExclusionConditions(AinterB, Ac, Bc));
			}
			else exclusionCondition.add(Bc);
		}
		if(exclusion) {
			C.getCondition().clear();
			C.getCondition().addAll(exclusionCondition);
		}
		return exclusion ? C : B; 	// If no change, then return B
	}
	
	private static boolean checkAllInterNotEmpty(Map<Conditions, CondElementType> AinterB, Conditions[] Ctypes, Map<Conditions, CondElementType> Ac, Map<Conditions, CondElementType> Bc) {
		boolean res = true;
		for(int i = 0; i < Ctypes.length && res; i++) {
			Conditions Ctype = Ctypes[i];
			res = res && interNotEmpty(AinterB, Ctype, Ac.get(Ctype), Bc.get(Ctype));
		}
		return res;
	}
	
	private static boolean interNotEmpty(Map<Conditions, CondElementType> AinterB, Conditions c, CondElementType a, CondElementType b) {
		if(a == null || b == null) return true;
		boolean res = false;
		try {
			CondElementType inter = a.inter(b);
			AinterB.put(c, inter);
			res = !inter.isEmpty();
		} catch (IncompatibleElementType e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	
	private static Set<Map<Conditions, CondElementType>> getExclusionConditions(Map<Conditions, CondElementType> AinterB, Map<Conditions, CondElementType> Ac, Map<Conditions, CondElementType> Bc) {
		Set<Map<Conditions, CondElementType>> res = new HashSet<Map<Conditions,CondElementType>>();
		Conditions[] CTypes = Conditions.values();
		for(int i = 0; i < CTypes.length; i++) {
			Map<Conditions, CondElementType> cond = new HashMap<Conditions, CondElementType>();
			Conditions Ci = CTypes[i];
			List<CondElementType> AminusB = getBMinusA(Ci, Ac.get(Ci), Bc.get(Ci));// Bi minus Ai
			for(int j = 0; j < i; j++) {	// Do not calculate Bi inter Ai again
				Conditions Cj = CTypes[j];
				CondElementType Oj = AinterB.get(Cj);
				if(Oj != null) cond.put(Cj, Oj);
			}
			for(int k = i + 1; k < CTypes.length; k++) {	// Bi
				Conditions Ck = CTypes[k];	
				CondElementType Ok = Bc.get(Ck);
				if(Ok != null) cond.put(Ck, Ok);
			}
			if(AminusB != null) {
				if(!AminusB.isEmpty()) {
					cond.put(Ci, AminusB.get(0));	// At least 1 element because Ai inter Bi is not empty
					res.add(cond);
					if(AminusB.size() > 1) {
						for(int l = 1; l < AminusB.size(); l++) {
							Map<Conditions, CondElementType> condl = new HashMap<Conditions, CondElementType>(cond);
							condl.put(Ci, AminusB.get(l));
							res.add(condl);
						}
					}
				}
			}

		}
		return res;
	}
	
	private static List<CondElementType> getBMinusA(Conditions c, CondElementType a, CondElementType b) {
		if(a == null && b == null) return null;
		if(a == null) return new ArrayList<CondElementType>();
		if(b == null) b = a.getDefaultAny();
		try {
			return b.minus(a);
		} catch (IncompatibleElementType e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**              End Algorithm 1               */

	/**
	 *               Begin Algorithm 2               
	 ***********************************************/
	
	public static int testIrrelevance(Component c, Rule r) {
		Topology topology = c.getTopology();
		Zone dzone = topology.getZoneFromAddress(r.getDzone());
		Zone szone = topology.getZoneFromAddress(r.getSzone());
		int irrelevance = 0;
		if(szone == null || dzone == null) return 0; // TODO gérer cas où règle chevauche plusieurs zones
		if(szone != null && dzone != null && szone == dzone) {
			irrelevance = 1;
		}
		else { 
			Set<Path> MR = topology.minimal_route(szone, dzone);
			boolean found = false;
			for(Path p : MR) {	// Check if a Minimal Route contains this component
				if(p.contains(c)) {
					found = true;
					break;
				}
			}
			if(!found) irrelevance = 2;
			else {
				CondElementType ac = r.getOrigCondition().get(Conditions.AC);
				if(ac != null 
						&& ac instanceof StringField 
						&& !dzone.getVulnerabilities().contains(((StringField) ac).getValue())) {
					irrelevance = 3;
				}
			}
		}
		return irrelevance;
	}
	
	/**              End Algorithm 2               */

	/**
	 *               Begin Algorithm 3               
	 ***********************************************/

	/**
	 * 
	 * note : R must not contains r
	 * @param R
	 * @param r 
	 */
	public static List<Rule> testRedundancy(List<Rule> R, Rule r) {
		Rule temp = r; 
		List<Rule> redundancyList = new LinkedList<Rule>();
		for(Rule rule : R) {
			if(rule.getDecision() == r.getDecision()
					&& !temp.getCondition().isEmpty() 
					&& !rule.getCondition().isEmpty()) {
				Rule ex = exclusion(temp, rule);
				if(ex != temp) {
					temp = ex;
					redundancyList.add(rule);
					if(temp.getCondition().isEmpty()) return redundancyList;
				}
			}
		}
		return new LinkedList<Rule>();
	}
	
	/**
	 * Does not depend on the rule decision when testing redundancy
	 * note : R must not contains r
	 * @param R
	 * @param r 
	 */
	public static List<Rule> testRedundancyAll(List<Rule> R, Rule r) {
		Rule temp = r; 
		List<Rule> redundancyList = new LinkedList<Rule>();
		for(Rule rule : R) {
			if(//rule.getDecision() != r.getDecision()
					//&&
					!temp.getCondition().isEmpty() 
					&& !rule.getCondition().isEmpty()) {
				Rule ex = exclusion(temp, rule);
				if(ex != temp) {
					temp = ex;
					redundancyList.add(rule);
					if(temp.getCondition().isEmpty()) return redundancyList;
				}
			}
		}
		return new LinkedList<Rule>();
	}

	
	/**              End Algorithm 3               */

	/**
	 *               Begin Algorithm 4               
	 ***********************************************/

	private static void phase1(Component c, List<Rule> R, List<AuditWarning> warning) {
		for(int i = 0; i < R.size() - 1; i++) {
			Rule Ri = R.get(i);
			for(int j = i + 1; j < R.size(); j++) {
				Rule Rj = R.get(j);
				if(Ri.getDecision() != Rj.getDecision() && !Rj.getCondition().isEmpty()) {
					Rule ex = exclusion(Rj, Ri);
					if(ex != Rj) {	// Rj, Ri not disjoint
						Rj.replaceWith(ex);
						Rj.addExclusionList(Ri);
						if(Rj.getCondition().isEmpty()) {
							Rj.setShadowing(true);
							warning.add(new AuditWarning(Warnings.SHADOWING,
									"Warning shadowing on " 
									+ crName(c, Rj) + " by " + crName(c, Rj.getExclusionList().iterator())
									, c, Rj));
						}
					}
				}
			}
		}
	}
	
	private static void phase2(Component c, List<Rule> R, List<AuditWarning> warning) {
		List<Rule> Ra = new LinkedList<Rule>(R);
		Collections.reverse(Ra);	// Reverse for redundancy ?
		for(int i = 0; i < R.size() - 1; i++) {
			Rule Ri = R.get(i);
			Ra.remove(Ri);
			if(Ri.getCondition().isEmpty()) continue;	// Rule already empty
			List<Rule> redundancyList = Algorithms.testRedundancy(Ra, Ri);
			if(!redundancyList.isEmpty()) {				// Redundancy found
				Ri.getExclusionList().addAll(redundancyList);
				Ri.getCondition().clear();
				Ri.setRedundancy(true);
				warning.add(new AuditWarning(Warnings.REDUNDANCY,
						"Warning redundancy on " 
						+ crName(c, Ri) + " with " + crName(c, Ri.getExclusionList().iterator())
						, c, Ri));
			}
			else {										// No redundancy, then check shadowing
				for(int j = i + 1; j < R.size(); j++) {
					Rule Rj = R.get(j);
					if(Ri.getDecision() == Rj.getDecision() 
							&& !Rj.getCondition().isEmpty()) {
						Rule ex = exclusion(Rj, Ri);
						if(ex != Rj) {	// Rj, Ri not disjoint
							Rj.replaceWith(ex);
							Rj.addExclusionList(Ri);
							if(Rj.getCondition().isEmpty()) {
								Rj.setShadowing(true);
								warning.add(new AuditWarning(Warnings.SHADOWING,
										"Warning shadowing on " 
										+ crName(c, Rj) +  " by " + crName(c, Rj.getExclusionList().iterator())
										, c, Rj));
							}
						}
					}
				}
			}
		}
	}

	private static void phase3(Component c, List<Rule> R, List<AuditWarning> warning) {
		int irrelevance = 0;
		for(Rule r : R) {
			if(!r.getCondition().isEmpty()
					&& (irrelevance = testIrrelevance(c, r)) > 0) {
				Warnings type = irrelevance == 1 ? Warnings.IRRELEVANCE1 
								: irrelevance == 2 ? Warnings.IRRELEVANCE2
								: Warnings.IRRELEVANCE3;
				warning.add(new AuditWarning(type, 
						"Warning case " + irrelevance + " of irrelevance on " 
						+ crName(c, r), c, r));
				r.getCondition().clear();
				r.setIrrelevance(true);
			}
		}
	}
	
	public static List<AuditWarning> intraComponentAudit(Component c, List<Rule> R) {
		List<AuditWarning> warning = new LinkedList<AuditWarning>();
		phase1(c, R, warning);
		phase2(c, R, warning);
		phase3(c, R, warning);
		return warning;
	}
	
	
	/**              End Algorithm 4               */

	/**
	 *               Begin Algorithm 5               
	 ***********************************************/
	
	public static void cleanAll(Topology t) {
		for(Component c : t.getComponents()) {
			c.setRules(Rule.cleanRules(c.getRules(), c.getDefaultPolicy()));
		}
	}

	public static List<AuditWarning> interComponentAudit(Topology t) {
		List<AuditWarning> warning = new LinkedList<AuditWarning>();
		for(Component c : t.getComponents()) {
			for(Rule r : c.getRules()) {
				IPv4Interval iS = (IPv4Interval) r.getCondition().iterator().next().get(Conditions.SZONE);
				IPv4Interval iD = (IPv4Interval) r.getCondition().iterator().next().get(Conditions.DZONE);
				List<Zone> Z2 = null;
				for(Zone z1 : t.getZones()) {
					if(z1.isInterInZone(iS)) { // z1 inter iS not empty
						if(Z2 == null) {
							Z2 = new ArrayList<Zone>();
							for(Zone z2 : t.getZones()) {
								if(z2.isInterInZone(iD)) { // z2 inter iD not empty
									Z2.add(z2);
									audit(c, r, z1, z2, warning);
								}
							}
						}
						else {
							for(Zone z2 : Z2) {
								audit(c, r, z1, z2, warning);
							}
						}
					}
				}
			}
		}
		return warning;
	}
	
	/**              End Algorithm 5               */
	
	/**
	 *               Begin Algorithm 6               
	 ***********************************************/
	
	public static void audit(Component c, Rule r, Zone z1, Zone z2, List<AuditWarning> warning) {
		Topology t = c.getTopology();
		for(Path p : t.minimal_route(z1, z2)) {
			if(p.contains(c)) {	// Only minimal route that contains this component
				Path pathDown = p.tail(c);
				Path pathUp = p.head(c);
				if(!pathDown.isEmpty() && r.getDecision() == false && c.getType() == CType.FIREWALL) {
					Component cDown = firstFirewall(pathDown);
					if(cDown != null) downstream(r, c, cDown, warning);
				}
				if(!pathUp.isEmpty()) {
					Component cUp = pathUp.last();
					if(cUp.getType() == CType.FIREWALL) upstream(r, c, cUp, warning);
				}
			}
		}
	}

	private static Component firstFirewall(Path p) {
		for(Component c : p.getComponents()) {
			if(c.getType() == CType.FIREWALL) return c;
		}
		return null;
	}
	
	private static List<Rule> correlated(Component c, Rule r, boolean decision) {
		List<Rule> R = new ArrayList<Rule>();
		//Map<Conditions, CondElementType> rCond = r.getCondition().iterator().next();
		//Conditions[] Ctypes = Conditions.values();
		for(Rule rc : c.getRules()) {
			if(rc.getDecision() == decision && isCorrelated(r, rc)) R.add(rc);
			/*Map<Conditions, CondElementType> AinterB = new HashMap<Conditions, CondElementType>();
			Map<Conditions, CondElementType> rcCond = rc.getCondition().iterator().next();
			if(decision == rc.getDecision() 
					&& checkAllInterNotEmpty(AinterB, Ctypes, rcCond, rCond)) {
				R.add(rc);
			}*/
		}
		return R;
	}
	
	private static boolean isCorrelated(Rule B, Rule A) {
		for(Map<Conditions, CondElementType> Ac : A.getCondition()) {
			boolean correlated = isCorrelated2(B, new Rule(A.getName(), A.getType(), Ac, A.getDecision()));
			if(correlated) return true;
		}
		return false;		
	}
	
	private static boolean isCorrelated2(Rule B, Rule A) {
		Conditions[] Ctypes = Conditions.values();
		Map<Conditions, CondElementType> Ac = A.getOrigCondition();
		for(Map<Conditions, CondElementType> Bc : B.getCondition()) {
			Map<Conditions, CondElementType> AinterB = new HashMap<Conditions, CondElementType>();
			if(checkAllInterNotEmpty(AinterB, Ctypes, Ac, Bc)) return true;
		}
		return false;
	}

	
	/**              End Algorithm 6               */

	/**
	 *               Begin Algorithm 7               
	 ***********************************************/

	public static void downstream(Rule r, Component c, Component cDown, List<AuditWarning> warning) {
		if(cDown.getDefaultPolicy() == true) {
			List<Rule> Rdf = correlated(cDown, r, false);
			if(Rdf.isEmpty()) {
				warning.add(new AuditWarning(Warnings.FULLMISCONNECTION,
						"Warning full misconnection " + crName(c, r) + " with " + cDown.getName()
						, c, r, cDown));
			}
			else if(testRedundancy(Rdf, r).isEmpty()) {
				warning.add(new AuditWarning(Warnings.PARTIALMISCONNECTION,
						"Warning partial misconnection to " + crName(c, r) + " with "
						+ crName(cDown, Rdf.iterator())
						, c, r, cDown));
			}
		}
	}
	
	/**              End Algorithm 7               */

	/**
	 *               Begin Algorithm 8               
	 ***********************************************/

	public static void upstream(Rule r, Component c, Component cUp, List<AuditWarning> warning) {
		List<Rule> Ruf = correlated(cUp, r, false);
		List<Rule> Rut = correlated(cUp, r, true);
		List<Rule> redundancyList;
		if(r.getDecision() == true) {
			redundancyList = testRedundancy(Rut, r); 
			if(!redundancyList.isEmpty()) {
				warning.add(new AuditWarning(Warnings.FULLREDUNDANCY,
						"Warning full redundancy " 
						+ crName(c, r) + " with " 
						+ crName(cUp, redundancyList.iterator())
						, c, r, cUp));
			}
			else if(!Rut.isEmpty()) {
				warning.add(new AuditWarning(Warnings.PARTIALREDUNDANCY,
						"Warning partial redundancy "
						+ crName(c, r) + " with "
						+ crName(cUp, Rut.iterator())
						, c, r, cUp));
			}
			else if(c.getType() == CType.FIREWALL) {
				redundancyList = testRedundancyAll(Ruf, r);
				if(!redundancyList.isEmpty()) {
					warning.add(new AuditWarning(Warnings.FULLMISCONNECTION,
							"Warning full misconnection "
							+ crName(c, r) + " with "
							+ crName(cUp, redundancyList.iterator())
							, c, r, cUp));
				}
				else if(!Ruf.isEmpty()) {
					warning.add(new AuditWarning(Warnings.PARTIALMISCONNECTION,
							"Warning partial misconnection "
							+ crName(c, r) + " with "
							+ crName(cUp, Ruf.iterator())
							, c, r, cUp));
				}
				else if(Ruf.isEmpty() && Rut.isEmpty() && cUp.getDefaultPolicy() == false) {
					warning.add(new AuditWarning(Warnings.FULLMISCONNECTION,
							"Warning full misconnection "
							+ crName(c, r) + " with "
							+ cUp.getName() + " {policy (false)}"
							, c, r, cUp));
				}
			}
		}
		else { 	// decision == false
			redundancyList = testRedundancyAll(Rut, r);
			if(!redundancyList.isEmpty()) {
				warning.add(new AuditWarning(Warnings.FULLSHADOWING,
						"Warning full shadowing "
						+ crName(c, r) + " with "
						+ crName(cUp, redundancyList.iterator())
						, c, r, cUp));
			}
			else if(!Rut.isEmpty()) {
				warning.add(new AuditWarning(Warnings.PARTIALSHADOWING,
						"Warning partial shadowing "
						+ crName(c, r) + " with "
						+ crName(cUp, Rut.iterator())
						, c, r, cUp));
			}
			else if(Ruf.isEmpty() && cUp.getDefaultPolicy() == true) {
				warning.add(new AuditWarning(Warnings.FULLSHADOWING,
						"Warning full shadowing "
						+ crName(c, r) + " with "
						+ cUp.getName() + "{policy (true)}"
						, c, r, cUp));
			}
			else if(testRedundancy(Ruf, r).isEmpty() && cUp.getDefaultPolicy() == true) {
				warning.add(new AuditWarning(Warnings.PARTIALSHADOWING,
						"Warning partial shadowing "
						+ crName(c, r) + " with "
						+ crName(cUp, Ruf.iterator())
						, c, r, cUp));
			}
		}
	}
	
	/**              End Algorithm 8               */

	/**
	 *               Begin Algorithm 9               
	 ***********************************************/
	
	public static void policyRewriting(List<Rule> R) {
		for(int i = 0; i < R.size() - 1; i++) {
			Rule Ri = R.get(i);
			for(int j = i + 1; j < R.size(); j++) {
				Rule Rj = R.get(j);
				if(Rj.getType() == Ri.getType()) {
					Rj.replaceWith(exclusion(Rj, Ri));
					if(Rj.getCondition().isEmpty()) R.remove(Rj);
				}
			}
		}
	}
	
	/**              End Algorithm 9               */
	
	/**
	 *               Begin Algorithm 10               
	 ***********************************************/

	public static List<Rule> aggregation(Topology t) {
		List<Rule> R = new ArrayList<Rule>();
		Collection<Component> C = t.getComponents();
		Collection<Zone> Z = t.getZones();
		for(Component c : C) {
			if(c.getType() != CType.UNKNOWN) {
				intraComponentAudit(c, c.getRules());
				c.setRules(Rule.cleanRules(c.getRules(), c.getDefaultPolicy()));
			}
		}
		for(Component c1 : C) {
			for(Rule r1 : c1.getRules()) {
				int i = 0;
				for(Zone z1 : Z) {
					IPv4Interval Sr1 = (IPv4Interval) r1.getOrigCondition().get(Conditions.SZONE);
					if(z1.isInterInZone(Sr1)) {
						for(Zone z2 : Z) {
							IPv4Interval Dr1 = (IPv4Interval) r1.getOrigCondition().get(Conditions.DZONE);
							if(z2.isInterInZone(Dr1)) {
								Set<Path> MR = t.minimal_route(z1, z2);								
								if(r1.getDecision() == false) {
									if(isAggregationError(MR, c1, r1)) {
										System.out.println("Aggregation error");
										return new ArrayList<Rule>();
									}
								}
								else { // decision == true
									if(c1.getType() == CType.FIREWALL) {
										for(Path p : MR) {
											if(!p.first().equals(c1)) {
												System.out.println("Aggregation error");
												return new ArrayList<Rule>();
											}
										}
									}
									else if(c1.getType() == CType.NIDS) {
										if(isAggregationError(MR, c1, r1)) {
											System.out.println("Aggregation error");
											return new ArrayList<Rule>();
										}
									}
								}
								for(IPv4Interval szone : z1.getNetwork()) {
									if(szone.inter(Sr1).isEmpty()) continue;
									for(IPv4Interval dzone : z2.getNetwork()) {
										if(dzone.inter(Dr1).isEmpty()) continue;
										i++;
										Rule Ri = new Rule(r1.getName() + "." + i , r1.getType(), 
												new HashMap<Conditions, CondElementType>(r1.getOrigCondition()), r1.getDecision());
										Ri.getOrigCondition().put(Conditions.SZONE, szone);
										Ri.getOrigCondition().put(Conditions.DZONE, dzone);
										if(!Ri.getCondition().isEmpty()) R.add(Ri);
									}
								}
							}
						}
					}
				}
			}
		}
		policyRewriting(R);
		return R;
	}
	
	private static boolean isAggregationError(Set<Path> MR, Component c1, Rule r1) {
		for(Path p : MR) {
			for(Component c2 : p.head(c1).getComponents()) {
				if(c2.getType() == CType.FIREWALL) {
					boolean c2rfEmpty = true;
					boolean c2rtEmpty = true;
					for(Rule r2 : c2.getRules()) {
						if(isCorrelated(r2, r1)) {
								if(r2.getDecision() == false) c2rfEmpty = false;
								else c2rtEmpty = false;
						}
						if(!c2rfEmpty && !c2rtEmpty) break;
					}
					if(c2rfEmpty) {
						if(!c2rtEmpty || c2.getDefaultPolicy() == true) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}
	
	/**              End Algorithm 10               */

	
}
