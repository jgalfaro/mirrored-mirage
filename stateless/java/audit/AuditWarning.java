package audit;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;

import model.Component;
import model.Rule;

public class AuditWarning {

	private final Warnings type;
	private final String message;
	private final Component c1;
	private final Rule r1;
	private final Component c2;
	
	public AuditWarning(Warnings type, String message, Component c, Rule r) {
		this(type, message, c, r, c);
	}
	
	public AuditWarning(Warnings type, String message, Component c1, Rule r1, Component c2) {
		this.type = type;
		this.message = message;
		this.c1 = c1;
		this.r1 = r1;
		this.c2 = c2;
	}

	public static String toString(List<AuditWarning> warning) {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		PrintStream p = new PrintStream(bout, true);
		for(AuditWarning w : warning) {
			if(w.c1 == w.c2) {
				p.println(Algorithms.crName(w.c1, w.r1) + " - " 
						+ w.type + " - " 
						+ w.message);
			}
			else p.println(Algorithms.crName(w.c1, w.r1) + ", " 
					+ w.c2.getName() + " - " + w.type + " - " 
					+ w.message);
		}
		return bout.toString();
	}
	
	public static String toString(Map<Component, List<AuditWarning>> warning) {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		PrintStream p = new PrintStream(bout, true);
		for(Component c : warning.keySet()) {
			p.println("*** Component " + c.getName() + "***");
			p.println(toString(warning.get(c)));
		}
		return bout.toString();
	}
	
	@Override
	public String toString() {
		String res = "";
		if(c1 == c2) {
			res = Algorithms.crName(c1, r1) + ", " 
					+ c2.getName() + " - " + type + " - "
					+ message;
		}
		else res = Algorithms.crName(c1, r1) + " - " 
					+ type + " - " 
					+ message;
		return res;
	}
	
}
