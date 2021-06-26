package main;

import io.SkyboxReader;
import io.Reader;
import io.Writer;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Iterator;

import javax.xml.parsers.ParserConfigurationException;

import model.Component;
import model.Topology;
import model.Zone;

import org.xml.sax.SAXException;

import audit.Algorithms;
import audit.Audit;
import audit.AuditWarning;
import exception.TopologyReaderException;
import exception.TopologyWriterException;

public class MainTestWriter {

	public static void main(String[] args) throws Exception {
            test1();
            test2();
            test3();
            testAuditWrite();
	}

	public static void test1() throws TopologyReaderException, ParserConfigurationException, SAXException, IOException, TopologyWriterException {
		Reader sr = new Reader("./test.xml");
		Topology t = sr.getTopology();
		Writer w = new Writer(t);
		Writer out = new BufferedWriter(new OutputStreamWriter(System.out));
		w.writeTopology(out);
		out.flush();
	}

	public static void test2() throws SAXException, IOException, ParserConfigurationException, TopologyReaderException, TopologyWriterException {
		Reader sr = new Reader("./test.xml");
		Topology t = sr.getTopology();
		Writer w = new Writer(t);
		Writer out = new BufferedWriter(new OutputStreamWriter(System.out));
		w.writeTopology(out);
		out.flush();
	}

	public static void test3() throws SAXException, IOException, ParserConfigurationException, TopologyReaderException, TopologyWriterException {
		Reader sr = new Reader("./test.xml");
		Topology t = sr.getTopology();
		Writer w = new Writer(t);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		Writer out = new BufferedWriter(new OutputStreamWriter(bout));
		w.writeTopology(out);
		out.flush();
		String xml1 = bout.toString();
		System.out.println("******** xml1 ********");
		//System.out.println(xml1);
		MainTestReader.printTopology(t);
		Reader sr2 = new Reader(new ByteArrayInputStream(bout.toByteArray()));
		Topology t2 = sr2.getTopology();
		Writer w2 = new Writer(t2);
		ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
		Writer out2 = new BufferedWriter(new OutputStreamWriter(bout2));
		w2.writeTopology(out2);
		out2.flush();
		String xml2 = bout2.toString();
		System.out.println("******** xml2 ********");
		MainTestReader.printTopology(t2);
		System.out.println(xml2);
	}

	public static void testAuditWrite() throws SAXException, IOException, ParserConfigurationException, TopologyReaderException, TopologyWriterException {
		SkyboxReader sr = new SkyboxReader("../xml-examples/20100206-sec1Net-intra-anom_inter_anom.xml");
		Topology t = sr.getTopology();
		System.out.println("Audit sur la topologie skybox...");
		Audit audit = new Audit(t);
		System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
//		Algorithms.cleanAll(t);
		System.out.println("Saving");
		Writer w = new Writer(t);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		Writer out = new BufferedWriter(new OutputStreamWriter(bout));
		w.writeTopology(out);
		out.flush();
//		System.out.println(bout.toString());
		System.out.println("Audit sur la topologie Télécom Bretagne générée...");
		Reader tr = new Reader(new ByteArrayInputStream(bout.toByteArray()));
		Topology t2 = tr.getTopology();
		Audit audit2 = new Audit(t2);
		System.out.println(AuditWarning.toString(audit2.intraComponentAudit()));
		Algorithms.cleanAll(t2);
		System.out.println(AuditWarning.toString(audit2.interComponentAudit()));

	}

	public static void testWrite() throws SAXException, IOException, ParserConfigurationException, TopologyReaderException, TopologyWriterException {
		SkyboxReader sr = new SkyboxReader("../xml-examples/20100206-sec1Net_inter_anom.xml");
		Topology t = sr.getTopology();
		Writer w = new Writer(t);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		Writer out = new BufferedWriter(new OutputStreamWriter(bout));
		w.writeTopology(out);
		out.flush();
		Reader r = new Reader(new ByteArrayInputStream(bout.toByteArray()));
		Topology t2 = r.getTopology();
		System.out.println(bout.toString());
		System.out.println("*** Audit t1 ***");
		//MainTestReader.printTopology(t, true);
		Audit audit = new Audit(t);
		System.out.println(AuditWarning.toString(audit.intraComponentAudit()));
		Algorithms.cleanAll(t);
		System.out.println(AuditWarning.toString(audit.interComponentAudit()));
		System.out.println("*** Audit t2 ***");
		//MainTestReader.printTopology(t2, true);
		Audit audit2 = new Audit(t2);
		System.out.println(AuditWarning.toString(audit2.intraComponentAudit()));
		Algorithms.cleanAll(t2);
		System.out.println(AuditWarning.toString(audit2.interComponentAudit()));
		compare(t, t2);
	}

	public static void testWrite() throws SAXException, IOException, ParserConfigurationException, TopologyReaderException, TopologyWriterException {
		Reader sr = new Reader("./test.xml");
		Topology t = sr.getTopology();
		Writer w2 = new Writer(t);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		Writer out = new BufferedWriter(new OutputStreamWriter(bout));
		w2.writeTopology(out);
		out.flush();
		String xml = bout.toString();
		//MainTestReader.printTopology(t);
		System.out.println("******** xml ********");
		System.out.println(xml);
	}



	/* **************** */


	/**
	 * Compare if t1 = t2
	 * @param t1
	 * @param t2
	 */
	private static void compare(Topology t1, Topology t2) {
		boolean ok = true;
		System.out.println("Checking components...");
		for(Component c : t1.getComponents()) {
			Component c2 = t2.getComponent(c.getName());
			if(c2 == null) {
				ok = false;
				System.out.println("t1 : " + c.getName() + " not in t2");
			}
			else if(c2.getDefaultPolicy() != c.getDefaultPolicy()) {
				ok = false;
				System.out.println("t1 : " + c.getName() + " default policy is different : " + c.getDefaultPolicy());
			}
			else if(c2.getType() != c.getType()) {
				ok = false;
				System.out.println("t1 : " + c.getName() + " type is different : " + c.getType());
			}
		}
		for(Component c : t2.getComponents()) {
			Component c2 = t1.getComponent(c.getName());
			if(c2 == null) {
				ok = false;
				System.out.println("t2 : " + c.getName() + " not in t1");
			}
			else if(c2.getDefaultPolicy() != c.getDefaultPolicy()) {
				ok = false;
				System.out.println("t1 : " + c.getName() + " default policy is different : " + c.getDefaultPolicy());
			}
			else if(c2.getType() != c.getType()) {
				ok = false;
				System.out.println("t1 : " + c.getName() + " type is different : " + c.getType());
			}
		}
		if(!ok) return;
		System.out.println("t1, t2 : Same components OK");
		System.out.println("Checking zones...");
		for(Zone z : t1.getZones()) {
			Zone z2 = t2.getZone(z.getName());
			if(z2 == null) {
				ok = false;
				System.out.println("t1 : " + z.getName() + " not in t2");
			}
			else if(!z.getNetwork().containsAll(z2.getNetwork())
					|| !z2.getNetwork().containsAll(z.getNetwork())) {
				ok = false;
				System.out.println("t1 : " + z.getName() + " in t2 but network different : " + z.getNetwork());
			}
		}
		for(Zone z : t2.getZones()) {
			Zone z2 = t1.getZone(z.getName());
			if(z2 == null) {
				ok = false;
				System.out.println("t2 : " + z.getName() + " not in t1");
			}
			else if(!z.getNetwork().containsAll(z2.getNetwork())
					|| !z2.getNetwork().containsAll(z.getNetwork())) {
				ok = false;
				System.out.println("t1 : " + z.getName() + " in t2 but network different : " + z.getNetwork());
			}
		}
		if(!ok) return;
		System.out.println("t1, t2 : Same zones OK");
		System.out.println("Checking connections...");
		for(Component c : t1.getComponents()) {
			Iterator<Component> it1 = c.getConnected();
			Iterator<Component> it2 = t2.getComponent(c.getName()).getConnected();
			while(it1.hasNext() && it2.hasNext()) {
				Component c1 = it1.next();
				Component c2 = it2.next();
				if(!t2.getComponent(c1.getName()).isConnected(t2.getComponent(c.getName()))) {
					ok = false;
					System.out.println(c1.getName() + " is not connected to " + c.getName() + " in t2");
				}
				if(!t1.getComponent(c2.getName()).isConnected(c)) {
					ok = false;
					System.out.println(c2.getName() + " is not connected to " + c.getName() + " in t1");
				}
			}
			if(it1.hasNext() || it2.hasNext()) {
				ok = false;
				System.out.println(c.getName() + " is not connected to the same components");
			}
		}
		if(!ok) return;
		System.out.println("t1, t2 : Same connections OK");
		System.out.println("Checking rules...");
		for(Component c : t1.getComponents()) {
			Component c2 = t2.getComponent(c.getName());
			// TODO
		}
	}

	private static void dump(Iterator it) {
		while(it.hasNext()) System.out.print(it.next() + "|");
		System.out.println();
	}

}
