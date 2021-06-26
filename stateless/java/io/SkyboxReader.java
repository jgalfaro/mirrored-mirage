package io;

import static util.IPv4Interval.BYTE;
import static util.IPv4Interval.EMPTY;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
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

public class SkyboxReader implements TopologyReader {
	
	private Document document;

	public SkyboxReader(InputStream in) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder constructor = factory.newDocumentBuilder();
		this.document = constructor.parse(in);
	}
	
	public SkyboxReader(String filename) throws SAXException, IOException, ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder constructeur = factory.newDocumentBuilder();
		File xml = new File(filename);
		this.document = constructeur.parse(xml);
	}
	
	@Override
	public Topology getTopology() throws TopologyReaderException {
		try {
			Topology t = new Topology();
			initNetwork(t, document.getElementsByTagName("network"));
			Map<String, Set<NetworkInterface>> interfaces = initInterface(t, document.getElementsByTagName("net_interface"));
			Map<String, Component> components = initHost(t, document.getElementsByTagName("host"), interfaces);
			initAccessRules(t, document.getElementsByTagName("access_rule"), components);
			return t;
		} catch (Exception e) {
			throw new TopologyReaderException(e);
		}
	}
	
	private void initNetwork(Topology t, NodeList networks) throws Exception {
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("id");tagnames.add("ip_address");tagnames.add("net_mask");
		tagnames.add("included_ip_ranges");tagnames.add("excluded_ip_ranges");
		for(int i = 0; i < networks.getLength(); i++) {
			Element n = (Element) networks.item(i);
			Map<String, Element> elt = Utilxml.getElementsByTagName(n, tagnames);
			String id = elt.get("id").getTextContent();
			String ipaddress = elt.get("ip_address").getTextContent();
			int netmask = Integer.parseInt(elt.get("net_mask").getTextContent());
			String includeIP = elt.get("included_ip_ranges").getTextContent();
			//String excludeIP = elt.get("excluded_ip_ranges").getTextContent();
			String[] Tip = ipaddress.split("\\.");
			int[] ip = new int[4];
			if(netmask != 0) {
				for(int j = 0; j < Tip.length; j++) ip[j] = Integer.parseInt(Tip[j]);
			}
			Zone z;
			switch(netmask) {
				case 24:
					z = t.addZone(id, new IPv4Interval(ip[0], ip[1], ip[2], BYTE));
					break;
				case 16:
					z = t.addZone(id, new IPv4Interval(ip[0], ip[1], BYTE, BYTE));
					break;
				case 8:
					z = t.addZone(id, new IPv4Interval(ip[0], BYTE, BYTE, BYTE));
					break;
				default:
					z = t.addZone(id);
			}
			if(!"".equals(includeIP)) addIntervalFromRanges(z.getNetwork(), includeIP);
		}
	}

	private Map<String, Component> initHost(Topology t, NodeList hosts, Map<String, Set<NetworkInterface>> interfaces)
			throws Exception {
		Map<String, Component> result = new HashMap<String, Component>();
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("id");tagnames.add("name_from_user");tagnames.add("system_type_enum");
		tagnames.add("primary_ip_address");
		for(int i = 0; i < hosts.getLength(); i++) {
			Element n = (Element) hosts.item(i);
			Map<String, Element> elt = Utilxml.getElementsByTagName(n, tagnames);
			String id = elt.get("id").getTextContent();
			String name = elt.get("name_from_user") == null ? id : elt.get("name_from_user").getTextContent();
			String type = elt.get("system_type_enum").getTextContent();
			Set<NetworkInterface> s = interfaces.get(id);
			if(s == null) s = new HashSet<NetworkInterface>();
			CType c = CType.UNKNOWN;
			if("Firewall".equals(type)) c = CType.FIREWALL;
			else if("NIDS".equals(type)) c = CType.NIDS;
			else if("Router".equals(type)) c = CType.ROUTER;
			if(c != CType.UNKNOWN) result.put(id, t.addComponent(name, c, s, true));
		}
		return result;
	}
	
	private Map<String, Set<NetworkInterface>> initInterface(Topology t, NodeList interfaces) throws Exception {
		Map<String, Set<NetworkInterface>> result = new HashMap<String, Set<NetworkInterface>>();
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("id");tagnames.add("ip_address");tagnames.add("name");
		tagnames.add("host_id");tagnames.add("network_id");
		for(int i = 0; i < interfaces.getLength(); i++) {
			Element n = (Element) interfaces.item(i);
			Map<String, Element> elt = Utilxml.getElementsByTagName(n, tagnames);
			String ipaddress = elt.get("ip_address").getTextContent();
			String hostid = elt.get("host_id").getTextContent();
			String id = elt.get("id").getTextContent();
			String networkid = elt.get("network_id") == null ? id : elt.get("network_id").getTextContent();
			Set<NetworkInterface> s = result.get(hostid);
			if(s == null) {
				s = new HashSet<NetworkInterface>();
				result.put(hostid, s);
			}
			Zone z = t.getZone(networkid);
			if(z != null) {
				if("".equals(ipaddress) || z.getNetwork().isEmpty()) {
					s.add(new NetworkInterface(EMPTY, z));
				}
				else {
					String[] ip = ipaddress.split("\\.");
					s.add(new NetworkInterface(
							new IPv4Interval(Integer.parseInt(ip[0]),
									Integer.parseInt(ip[1]),
									Integer.parseInt(ip[2]),
									Integer.parseInt(ip[3])), z));
				}
			}
		}
		return result;
	}
	
	private void initAccessRules(Topology t, NodeList rules, Map<String, Component> C) throws Exception {
		Set<String> tagnames = new HashSet<String>();
		tagnames.add("id");tagnames.add("source_ip_space_ip_ranges");
		tagnames.add("target_ip_space_ip_ranges");tagnames.add("firewall_space_firewall_services");
		tagnames.add("host_id");tagnames.add("action_type_enum");tagnames.add("nids_misc");
		for(int i = 0; i < rules.getLength(); i++) {
			Element n = (Element) rules.item(i);
			Map<String, Element> elt = Utilxml.getElementsByTagName(n, tagnames);
			String hostid = elt.get("host_id").getTextContent();
			String id = elt.get("id").getTextContent();
			String szone = elt.get("source_ip_space_ip_ranges").getTextContent();
			String dzone = elt.get("target_ip_space_ip_ranges").getTextContent();
			String portProtocol = elt.get("firewall_space_firewall_services").getTextContent();
			Element nids_node = elt.get("nids_misc");
			String nids_misc = nids_node == null ? null : nids_node.getTextContent(); 
			boolean decision = "2".equals(elt.get("action_type_enum").getTextContent());
			
			Component c = C.get(hostid);
			
			Map<Conditions, CondElementType> cond = new HashMap<Conditions, CondElementType>();
			Set<IPv4Interval> Sszone  = new HashSet<IPv4Interval>();
			Set<IPv4Interval> Sdzone  = new HashSet<IPv4Interval>();
			addIntervalFromRanges(Sszone, szone);
			addIntervalFromRanges(Sdzone, dzone);
			cond.put(Conditions.SZONE, Sszone.iterator().next());		
			cond.put(Conditions.DZONE, Sdzone.iterator().next());
			if(nids_misc != null) cond.put(Conditions.PAYLOAD, new StringField(nids_misc));
			Set<Map<Conditions, CondElementType>> conds = getPortProtocolInfos(cond, portProtocol);
			if("default_policy".equals(id) 
					|| ("0.0.0.0-255.255.255.255".equals(szone)
						&& "0.0.0.0-255.255.255.255".equals(dzone)
						&& "1-65535/1-65535/ANY".equals(portProtocol))) {
				c.setDefaultPolicy(decision);
			}
			else {
				List<Rule> ruleList = c.getRules();
				if(conds.size() == 1) {
					ruleList.add(new Rule("R" + id,
						c.getType() == CType.FIREWALL ? RType.FILTERING : RType.ALERTING, 
								conds.iterator().next(), decision));
				}
				else {
					int j = 0;
					for(Map<Conditions, CondElementType> condition : conds) {
						j++;
						ruleList.add(new Rule("R" + id + "." + j,
								c.getType() == CType.FIREWALL ? RType.FILTERING : RType.ALERTING, 
								condition, decision));
					}
				}

			}
		}
	}
	
	private Set<Map<Conditions, CondElementType>> getPortProtocolInfos(Map<Conditions, CondElementType> cond, String infos) throws IntervalException {
		Set<Map<Conditions, CondElementType>> result = new HashSet<Map<Conditions,CondElementType>>();
		String P[] = infos.split(",");
		for(String p : P) {
			Map<Conditions, CondElementType> m = new HashMap<Conditions, CondElementType>(cond);
			String[] I = p.split("/");
			String protocol = I[2].toLowerCase();
			if(!"any".equals(protocol)) m.put(Conditions.PROTOCOL, new ProtocolSet(protocol));
			PortInterval max = new PortInterval(1, PortInterval.MAX);
			PortInterval sport = getPortInterval(I[0]);
			PortInterval dport = getPortInterval(I[1]);
			if(!sport.equals(max)) m.put(Conditions.SPORT, sport);
			if(!dport.equals(max)) m.put(Conditions.DPORT, dport);
			result.add(m);
		}
		return result;
	}
	
	private PortInterval getPortInterval(String range) throws IntervalException {
		String[] R = range.split("-");
		int a = Integer.parseInt(R[0]);
		int b = Integer.parseInt(R[1]);
		return new PortInterval(a, b);
	}
	
	protected static void addIntervalFromRanges(Set<IPv4Interval> network, String range) throws IPv4IntervalException, IntervalException {
		String[] ranges = range.split(",");
		for(String r : ranges) {
			String[] Tip = r.split("-");
			String[] Tip1 = Tip[0].split("\\.");
			String[] Tip2 = Tip[1].split("\\.");
			int[] ip1 = new int[4];
			int[] ip2 = new int[4];
			for(int j = 0; j < 4; j++) {
				ip1[j] = Integer.parseInt(Tip1[j]);
				ip2[j] = Integer.parseInt(Tip2[j]);
			}
			network.add(new IPv4Interval(
							new Interval(ip1[0], ip2[0]),
							new Interval(ip1[1], ip2[1]),
							new Interval(ip1[2], ip2[2]),
							new Interval(ip1[3], ip2[3])));
		}
	}
	
}
