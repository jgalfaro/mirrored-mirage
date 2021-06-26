package io;

import model.Topology;
import exception.TopologyReaderException;

public interface TopologyReader {

	public Topology getTopology() throws TopologyReaderException;
	
}
