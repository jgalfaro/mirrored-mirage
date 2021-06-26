package io;

import static util.IPv4Interval.BYTE;

import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import model.CType;
import model.Component;
import model.CondElementType;
import model.Conditions;
import model.Rule;
import model.Topology;
import model.Zone;
import util.IPv4Interval;
import util.Interval;
import util.ProtocolSet;
import util.StringField;
import exception.TopologyWriterException;

public class Writer implements TopologyWriter {

	private final Topology t;
	
	public Writer(Topology t) {
		this.t = t;
	}
	
	@Override
	public void writeTopology(Writer out) throws TopologyWriterException {
		try {
			out.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			out.write("<topology>\n");
			// Hosts
			writeHosts(out);
			// Rules
			writeRules(out);
			// Zones
			writeZones(out);
			// Connections
			writeConnections(out);
			out.write("</topology>");
		} catch (Exception e) {
			throw new TopologyWriterException(e);
		}
	}

	private void writeHosts(Writer out) throws IOException {
		out.write(" <hosts>\n");
		Collection<Component> components = t.getComponents();
		for(Component c : components) {
			String type = CType.FIREWALL.equals(c.getType()) ? "Firewall" :
							CType.NIDS.equals(c.getType()) ? "NIDS" : "Unknown";
			out.write("  <host name=\"" + c.getName() + "\"" 
					+ " id=\"" + c.getName() + "\""
					+ " type=\"" + type + "\""
					+" IP_address=\"255.255.255.255\"></host>\n");
		}
		out.write(" </hosts>\n");
	}
	
	private void writeRules(Writer out) throws IOException {
		out.write(" <rules>\n");
		Collection<Component> components = t.getComponents();
		for(Component c : components) {
			String type = CType.FIREWALL.equals(c.getType()) ? "Firewall" :
				CType.NIDS.equals(c.getType()) ? "NIDS" : "Unknown";
			out.write("  <fw name=\"" + c.getName() + "\" type=\"" + type + "\">\n");
			List<Rule> rules = c.getRules();
			for(Rule r : rules) {
				if(r.getCondition().isEmpty()) continue;
				out.write("   <rule>\n");
				out.write("    <condition>\n");
				String nids_misc = "";
				for(Map<Conditions, CondElementType> cond : r.getCondition()) {
					ProtocolSet ps = (ProtocolSet)cond.get(Conditions.PROTOCOL);
					Set<String> protocoles = (ps == null) ? new HashSet<String>() : ps.getProtocols();
					String p = "";
					if(protocoles.isEmpty()) p = "1,2";
					else if(protocoles.contains("tcp")) {
						if(protocoles.contains("udp")) p = "1,2";
						else p = "1,1";
					} else p = "2,2";
					out.write("     <subcondition>\n");
					out.write("      <s>" + convertIpRange((IPv4Interval) cond.get(Conditions.SZONE)) + "</s>\n");
					out.write("      <d>" + convertIpRange((IPv4Interval) cond.get(Conditions.DZONE)) + "</d>\n");
					out.write("      <sP>" + convertIntervalRange((Interval) cond.get(Conditions.SPORT), 65535) + "</sP>\n");
					out.write("      <dP>" + convertIntervalRange((Interval) cond.get(Conditions.DPORT), 65535) + "</dP>\n");
					out.write("      <p>" + p + "</p>\n");
					out.write("     </subcondition>\n");
					if(cond.get(Conditions.PAYLOAD) != null) nids_misc = ((StringField) cond.get(Conditions.PAYLOAD)).toString();  
				}
				out.write("    </condition>\n");
				String decision = r.getDecision() ? "accept" : "deny";
				out.write("    <decision>" + decision + "</decision>\n");
				out.write("    <shadowing>" + r.isShadowing() + "</shadowing>\n");
				out.write("    <redundancy>"+ r.isRedundancy() +"</redundancy>\n");
				out.write("    <nids_misc>" + nids_misc + "</nids_misc>\n");
				out.write("   </rule>\n");
			}
			String policy = c.getDefaultPolicy() ? "open" : "close";
			out.write("   <policy>" + policy + "</policy>\n");
			out.write("  </fw>\n");
		}
		out.write(" </rules>\n");
	}
	
	private void writeZones(Writer out) throws IOException {
		Collection<Zone> zones = t.getZones();
		out.write(" <zones>\n");
		for(Zone z : zones) {
			out.write("  <zone name=\"" + z.getName() + "\""
					+		" id=\"Z" + z.getName() + "\"" +">\n");
			Set<IPv4Interval> networks = z.getNetwork();
			out.write("   <included>\n");
			if(networks.isEmpty()) out.write("    FF:FF:FF:FF:FF:FF/0\n");
			else out.write("    " + convertNetworkSet(networks) + "\n");
			out.write("   </included>\n");
			out.write("   <excluded>\n");
			out.write("   </excluded>\n");
			out.write("  </zone>\n");
		}
		out.write(" </zones>\n");
	}
	
	private void writeConnections(Writer out) throws IOException {
		Collection<Zone> zones = t.getZones();
		out.write(" <connections>\n");
		for(Zone z : zones) {
			for(Component c : z.getComponents()) {
				out.write("  <adjacent host_id=\"" + c.getName() + "\"" +
						" zone_id=\"Z" + z.getName() + "\"" +
						">\n");
				out.write("   " + c.getName() + ",Z" + z.getName() + "\n");
				out.write("  </adjacent>\n");
			}
		}
		out.write(" </connections>\n");
	}
	
	protected static String convertIpRange(IPv4Interval ipv4) {
		Interval A = ipv4.getA();
		Interval B = ipv4.getB();
		Interval C = ipv4.getC();
		Interval D = ipv4.getD();
		String part1 = "" + A.getBegin() + "." + B.getBegin() + "." + C.getBegin() + "." + D.getBegin();
		String part2 = "" + A.getEnd() + "." + B.getEnd() + "." + C.getEnd() + "." + D.getEnd();
		return part1 + "," + part2;
	}
	
	protected static String convertIntervalRange(Interval i, int max) {
		return (i == null) ? "1," + max : i.getBegin() + "," + i.getEnd(); 
	}
	
	protected static String convertNetworkSet(Set<IPv4Interval> s) {
		String res = "";
		Iterator<IPv4Interval> it = s.iterator();
		res += convertIntervalToNetwork(it.next());
		while(it.hasNext()) {
			res += "," + convertIntervalToNetwork(it.next());
		}
		return res;
	}
	
	protected static String convertIntervalToNetwork(IPv4Interval ipv4) {
		Interval A = ipv4.getA();
		Interval B = ipv4.getB();
		Interval C = ipv4.getC();
		Interval D = ipv4.getD();
		int n = A.equals(BYTE) ? 0 : B.equals(BYTE) ? 8 : C.equals(BYTE) ? 16 : D.equals(BYTE) ? 24 : 32;
		String v = "";
		switch(n) {
			case 0:
				v = "FF.FF.FF.FF.FF.FF";
			break;
			case 8:
				v = A.getBegin() + ".0.0.0";
			break;
			case 16:
				v = A.getBegin() + "." + B.getBegin() + ".0.0";
			break;
			case 24:
				v = A.getBegin() + "." + B.getBegin() + "." + C.getBegin() + ".0";
			break;
			default:
				v = A.getBegin() + "." + B.getBegin() + "." + C.getBegin() + "." + D.getBegin();
		}
		return v + "/" + n;
	}
	
}
