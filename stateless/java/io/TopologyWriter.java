package io;

import java.io.Writer;

import exception.TopologyWriterException;

public interface TopologyWriter {

	public void writeTopology(Writer out) throws TopologyWriterException;
	
}
