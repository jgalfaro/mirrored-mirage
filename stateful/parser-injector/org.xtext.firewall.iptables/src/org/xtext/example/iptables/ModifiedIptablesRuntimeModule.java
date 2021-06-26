package org.xtext.example.iptables;

import org.eclipse.xtext.linking.ILinker;

public class ModifiedIptablesRuntimeModule extends AbstractIptablesRuntimeModule{
	@Override
	public Class<? extends ILinker> bindILinker(){
		return IptablesLinker.class;
	}
}



