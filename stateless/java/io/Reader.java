package io;

import static util.IPv4Interval.BYTE;
import static util.IPv4Interval.EMPTY;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import model.CType;
import model.Component;
import model.CondElementType;
import model.Conditions;
import model.NetworkInterface;
import model.RType;
import model.Rule;
import model.Topology;
import model.Zone;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import util.IPv4Interval;
import util.Interval;
import util.PortInterval;
import util.ProtocolSet;
import util.StringField;
import exception.IPv4IntervalException;
import exception.IntervalException;
import exception.TopologyReaderException;

public class Reader implements TopologyReader {

	private Document document;
	
	public Reader(InputStream in) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder constructor = factory.newDocumentBuilder();
		this.document = constructor.parse(in);
	}
	
	public Reader(String filename) throws SAXException, IOException, ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder constructor = factory.newDocumentBuilder();
		File xml = new File(filename);
		this.document = constructor.parse(xml);
	}
	
	@Override
	public Topology getTopology() throws TopologyReaderException {
		try {
			Topology t = new Topology();
			initZones(t, document.getElementsByTagName("zone"));
			Map<String, Set<NetworkInterface>> interfaces = initInterface(t, document.getElementsByTagName("adjacent"));
			initHost(t, document.getElementsByTagName("host"), interfaces);
			initRules(t, document.getElementsByTagName("fw"));
			return t;
		} catch (Exception e) {
			throw new TopologyReaderException(e);
		}
	}
	
	private void initZones(Topology t, NodeList zones) throws Exception {
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("included");tagnames.add("excluded");
		for(int i = 0; i < zones.getLength(); i++) {
			Element n = (Element) zones.item(i);
			Map<String, Element> elt = Utilxml.getElementsByTagName(n, tagnames);
			String included = elt.get("included").getTextContent().trim();
			//String excluded = elt.get("excluded").getTextContent();	// Useless
			String name = n.getAttribute("name");
			//String id = n.getAttribute("id");						// Useless
			Zone z = t.addZone(name);
			if(!"FF:FF:FF:FF:FF:FF/0".equals(included)) addIntervalFromRanges(z.getNetwork(), included);
		}
	}

	private Map<String, Set<NetworkInterface>> initInterface(Topology t, NodeList interfaces) throws Exception {
		Map<String, Set<NetworkInterface>> result = new HashMap<String, Set<NetworkInterface>>();
		for(int i = 0; i < interfaces.getLength(); i++) {
			Element n = (Element) interfaces.item(i);
			String hostid = n.getAttribute("host_id");
			String zoneid = n.getAttribute("zone_id");
			Set<NetworkInterface> s = result.get(hostid);
			if(s == null) {
				s = new HashSet<NetworkInterface>();
				result.put(hostid, s);
			}
			Zone z = t.getZone(zoneid.substring(1));
			if(z != null) s.add(new NetworkInterface(EMPTY, z));
		}
		return result;
	}
	
	private void initHost(Topology t, NodeList hosts, Map<String, Set<NetworkInterface>> interfaces) throws Exception {
		for(int i = 0; i < hosts.getLength(); i++) {
			Element n = (Element) hosts.item(i);
			String name = n.getAttribute("name");
			String type = n.getAttribute("type");
			CType ctype = "Firewall".equals(type) ? CType.FIREWALL
							: "NIDS".equals(type) ? CType.NIDS : CType.UNKNOWN;
			t.addComponent(name, ctype, interfaces.get(name));
		}	
	}
	
	private void initRules(Topology t, NodeList fws) throws Exception {
		for(int i = 0; i < fws.getLength(); i++) {
			Element n = (Element) fws.item(i);
			String name = n.getAttribute("name");
			Component c = t.getComponent(name);
			NodeList list = n.getChildNodes();
			int nbRules = 0;
			RType ruleType = n.getAttribute("type").equals("Firewall") ? RType.FILTERING : RType.ALERTING;
			for(int j = 0; j < list.getLength(); j++) {
				Node item = list.item(j);
				if("rule".equals(item.getNodeName())) {
					nbRules++;
					c.getRules().add(getRule(item, nbRules, ruleType));
				}
				else if("policy".equals(item.getNodeName())) {
					c.setDefaultPolicy("open".equals(item.getTextContent()));
				}
			}
		}
	}
	
	private static Rule getRule(Node rule, int nbRules, RType ruleType) throws Exception {
		boolean decision = true;
		NodeList list = rule.getChildNodes();
		Map<Conditions, CondElementType> condition = new HashMap<Conditions, CondElementType>();
		String nids_misc = "";
		// Need NIDS_MISC first
		for(int i= 0; i < list.getLength(); i++) {
			Node item = list.item(i);
			if("nids_misc".equals(item.getNodeName())) {
				nids_misc = item.getTextContent();
				break;
			}
		}
		// Get decision and condition
		for(int i= 0; i < list.getLength(); i++) {
			Node item = list.item(i);
			if("decision".equals(item.getNodeName()) && "deny".equals(item.getTextContent())) decision = false;
			if("condition".equals(item.getNodeName())) addRuleCondition(condition, item, nids_misc);
		}
		return new Rule("R" + nbRules, ruleType, condition, decision);
	}
	
	private static void addRuleCondition(Map<Conditions, CondElementType> condition, Node cond, String nids_misc) throws DOMException, IntervalException {
		NodeList list = cond.getChildNodes();
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("s");tagnames.add("d");tagnames.add("sP");tagnames.add("dP");
		tagnames.add("p");
		for(int i= 0; i < list.getLength(); i++) {
			Node item = list.item(i);
			if("subcondition".equals(item.getNodeName())) {
				Map<String, Element> elt = Utilxml.getElementsByTagName((Element) item, tagnames);
				if(!elt.isEmpty()) {
					condition.put(Conditions.DPORT, getPortInterval(elt.get("dP").getTextContent()));
					condition.put(Conditions.SPORT, getPortInterval(elt.get("sP").getTextContent()));
					condition.put(Conditions.SZONE, addRuleIntervalFromRanges(elt.get("s").getTextContent()));
					condition.put(Conditions.DZONE, addRuleIntervalFromRanges(elt.get("d").getTextContent()));
					Set<String> s = new HashSet<String>();
					if(elt.get("p").getTextContent().contains("1")) s.add("tcp");
					if(elt.get("p").getTextContent().contains("2")) s.add("udp");
					condition.put(Conditions.PROTOCOL, new ProtocolSet(s));
					if(!"".equals(nids_misc)) condition.put(Conditions.PAYLOAD, new StringField(nids_misc));
				}
			}
		}
	}
		
	protected static PortInterval getPortInterval(String range) throws IntervalException {
		String[] R = range.split(",");
		int a = Integer.parseInt(R[0]);
		int b = Integer.parseInt(R[1]);
		return new PortInterval(a, b);
	}

	protected static IPv4Interval addRuleIntervalFromRanges(String range) throws IPv4IntervalException, IntervalException {
		String[] ranges = range.split(",");
		String range1 = ranges[0];
		String range2 = ranges[1];
		String[] Tip1 = range1.split("\\.");
		int[] ip1 = new int[4];
		for(int i = 0; i < 4; i++) {ip1[i] = Integer.parseInt(Tip1[i]);}
		String[] Tip2 = range2.split("\\.");
		int[] ip2 = new int[4];
		for(int i = 0; i < 4; i++) {ip2[i] = Integer.parseInt(Tip2[i]);}
		IPv4Interval ipv4 = (ip1[0] != ip2[0]) ? new IPv4Interval(new Interval(ip1[0], ip2[0]), BYTE, BYTE, BYTE)
							: (ip1[1] != ip2[1]) ? new IPv4Interval(new Interval(ip1[0]), new Interval(ip1[1], ip2[1]), BYTE, BYTE)
							: (ip1[2] != ip2[2]) ? new IPv4Interval(new Interval(ip1[0]), new Interval(ip1[1]), new Interval(ip1[2], ip2[2]), BYTE)
							: new IPv4Interval(new Interval(ip1[0]), new Interval(ip1[1]), new Interval(ip1[2]), new Interval(ip1[3], ip2[3]));
		return ipv4;
	}
	
	protected static void addIntervalFromRanges(Set<IPv4Interval> network, String range) throws IPv4IntervalException, IntervalException {
		String[] ranges = range.split(",");
		for(String r : ranges) {
			String[] Tip = r.split("/");
			String[] Tip1 = Tip[0].split("\\.");
			int n = Integer.parseInt(Tip[1]);
			if(n > 0) {
				int[] ip1 = new int[4];
				for(int j = 0; j < 4; j++) {
					ip1[j] = Integer.parseInt(Tip1[j]);
				}
				Interval A = new Interval(ip1[0]);
				Interval B = n > 8 ? new Interval(ip1[1]) : IPv4Interval.BYTE;
				Interval C = n > 16 ? new Interval(ip1[2]) : IPv4Interval.BYTE;
				Interval D = n > 24 ? new Interval(ip1[3]) : IPv4Interval.BYTE;
				network.add(new IPv4Interval(A, B, C, D));
			}
		}
	}
	
}
