package model;

public enum Conditions {
	SZONE(0),			// Source zone
	DZONE(1),			// Destination zone
	SPORT(2),			// Source port
	DPORT(3),			// Destination port
	PROTOCOL(4),		// Protocol
	AC(5),				// Attack class
	PAYLOAD(6);			// Payload
	
	private final int value; 
	
	private Conditions(int value) {
		this.value = value;
	}
	
	public int getValue() {
		return value;
	}
	
}
