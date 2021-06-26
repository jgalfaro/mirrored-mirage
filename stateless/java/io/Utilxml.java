package io;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Utilxml {

	public static Map<String, Element>getElementsByTagName(Element element, Set<String> tagnames) {
		Map<String, Element> result = new HashMap<String, Element>();
		NodeList childs = element.getChildNodes();
		for(int i = 0; i <  childs.getLength(); i++) {
			Node n = childs.item(i);
			if(n instanceof Element) {
				Element e = (Element) childs.item(i);
				if(tagnames.contains(e.getTagName())) result.put(e.getTagName(), e);
			}
		}
		return result;
	}
	
}
