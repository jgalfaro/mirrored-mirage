package audit;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import model.CType;
import model.Component;
import model.Rule;
import model.Topology;

public class Audit {

	private final Topology topology;
	
	public Audit(Topology t) {
		this.topology = t;
	}
	
	public Topology getTopology() {
		return topology;
	}
	
	public List<AuditWarning> intraComponentAudit(Component c) {
		return Algorithms.intraComponentAudit(c, c.getRules());
	}

	public Map<Component, List<AuditWarning>> intraComponentAudit() {
		Map<Component, List<AuditWarning>> res = new HashMap<Component, List<AuditWarning>>();
		for(Component c : topology.getComponents()) {
			if(c.getType() == CType.FIREWALL
					|| c.getType() == CType.NIDS) res.put(c, intraComponentAudit(c));
		}
		return res;
	}
	
	public List<AuditWarning> interComponentAudit() {
		return Algorithms.interComponentAudit(topology);
	}

	public List<Rule> aggregation() {
		return Algorithms.aggregation(topology);
	}
	
}
