package model;

import exception.IPAddressAlreadyUsedException;
import exception.NotInZoneException;
import util.IPv4Interval;

public class NetworkInterface {

	private final IPv4Interval ipaddress;
	
	private final Zone zone;
	
	public NetworkInterface(IPv4Interval ipaddress, Zone zone) throws NotInZoneException, IPAddressAlreadyUsedException {
		if(!ipaddress.isEmpty()) {
			if(!ipaddress.isSingleton()) throw new NotInZoneException(ipaddress);
			if(!zone.isInZone(ipaddress)) throw new NotInZoneException(ipaddress, zone.getNetwork());
			if(zone.contains(ipaddress)) throw new IPAddressAlreadyUsedException(ipaddress, zone.getNetwork());
		}
		this.ipaddress = ipaddress;
		this.zone = zone;
	}
	
	public IPv4Interval getIPAddress() {
		return ipaddress;
	}

	public Zone getZone() {
		return zone;
	}

}
