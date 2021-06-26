package org.xtext.example.iptables;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EClassifier;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EStructuralFeature;
import org.eclipse.xtext.diagnostics.IDiagnosticProducer;
import org.eclipse.xtext.linking.lazy.LazyLinker;
import org.eclipse.xtext.nodemodel.INode;

import com.google.common.collect.Multimap;

public class IptablesLinker  extends LazyLinker{
	@SuppressWarnings("unchecked")
	@Override
	protected void installProxies(EObject obj,
		IDiagnosticProducer producer,	Multimap<EStructuralFeature.Setting, INode> settingsToLink){
		//Remember to call the super implementation.
		super.installProxies(obj, producer, settingsToLink);
		if(obj.eClass().getEStructuralFeature("syn")!=null){
			//Of course, you can use NodeModelUtils here.
			if ((Boolean)obj.eGet(obj.eClass().getEStructuralFeature("syn")) == true){
				
				EClassifier ec = obj.eClass().getEPackage().getEClassifier("TCPFlag");
				EObject flag = obj.eClass().getEPackage().getEFactoryInstance().create((EClass) ec);
				flag.eSet(flag.eClass().getEStructuralFeature("name"), "SYN");
				((EList<EObject>)obj.eGet(obj.eClass().getEStructuralFeature("flags"))).add(flag);
			}
			
		}
	}
}
