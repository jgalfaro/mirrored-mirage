package util;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import model.CondElementType;
import exception.IncompatibleElementType;

public class ProtocolSet implements CondElementType {

	/** The ANY protocol set : {tcp, upd, icmp} */
	public static final ProtocolSet ANY = getAny();
	
	private final Set<String> protocols;			// Protocols in this ProtocolSet 

	/**
	 * Creates a ProtocolSet with a single protocol.
	 * @param protocol The single protocol in this ProtocolSet.
	 */
	public ProtocolSet(String protocol) {
		this.protocols = new HashSet<String>();
		this.protocols.add(protocol);
	}
	
	/**
	 * Creates a ProtocolSet with a Set of protocols.
	 * @param protocols Set of protocols.
	 */
	public ProtocolSet(Set<String> protocols) {
		this.protocols = protocols;
	}
	
	/**
	 * Get the protocol set.
	 * @return The protocol set.
	 */
	public Set<String> getProtocols() {
		return protocols;
	}
	
	/**
	 * Get the ANY ProtocolSet : {tcp, udp, icmp}.
	 * @return The ANY ProtocolSet
	 */
	private static ProtocolSet getAny() {
		Set<String> protocols = new HashSet<String>();
		protocols.add("tcp");
		protocols.add("udp");
		protocols.add("icmp");
		return new ProtocolSet(protocols);
	}
	
	/**
	 * Get the intersection between this ProtocolSet and b.
	 * @param b A valid ProtocolSet.
	 * @return The intersection between this ProtocolSet and b.
	 */
	public ProtocolSet inter(ProtocolSet b) {
		ProtocolSet res = new ProtocolSet(new HashSet<String>(protocols));
		res.protocols.retainAll(b.protocols);
		return res;
	}
	
	/**
	 * Get the list of ProtocolSet that represents this ProtocolSet minus b.
	 * @param b	A valid ProtocolSet.
	 * @return The list of ProtocolSet that represents this ProtocolSet minus b.<br />
	 * <code>{tcp, udp} - {udp} = [{tcp}]</code><br />
	 * <code>{tcp, udp} - ANY = []</code><br />
	 * The size list is always equal or less than 1.
	 */
	public List<ProtocolSet> minus(ProtocolSet b) {
		List<ProtocolSet> res = new LinkedList<ProtocolSet>();
		ProtocolSet p = new ProtocolSet(new HashSet<String>(protocols));
		p.protocols.removeAll(b.protocols);
		if(!p.protocols.isEmpty()) res.add(p);
		return res;
	}
	
	@Override
	public CondElementType getDefaultAny() {
		return ANY;
	}

	@Override
	public CondElementType inter(CondElementType c) throws IncompatibleElementType {
		if(c instanceof ProtocolSet) return inter((ProtocolSet) c);
		throw new IncompatibleElementType(this, c);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<CondElementType> minus(CondElementType c) throws IncompatibleElementType {
		if(c instanceof ProtocolSet) return (List) minus((ProtocolSet) c);
		throw new IncompatibleElementType(this, c);
	}

	@Override
	public boolean isEmpty() {
		return protocols.isEmpty();
	}
	
	@Override
	public String toString() {
		return protocols.toString();
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof ProtocolSet) {
			ProtocolSet p = (ProtocolSet) obj;
			return protocols.equals(p.protocols);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return protocols.hashCode();
	}
	
}
