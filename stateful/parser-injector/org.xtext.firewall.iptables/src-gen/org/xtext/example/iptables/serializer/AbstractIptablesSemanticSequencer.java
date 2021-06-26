package org.xtext.example.iptables.serializer;

import com.google.inject.Inject;
import com.google.inject.Provider;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.xtext.serializer.acceptor.ISemanticSequenceAcceptor;
import org.eclipse.xtext.serializer.acceptor.SequenceFeeder;
import org.eclipse.xtext.serializer.diagnostic.ISemanticSequencerDiagnosticProvider;
import org.eclipse.xtext.serializer.diagnostic.ISerializationDiagnostic.Acceptor;
import org.eclipse.xtext.serializer.sequencer.AbstractSemanticSequencer;
import org.eclipse.xtext.serializer.sequencer.GenericSequencer;
import org.eclipse.xtext.serializer.sequencer.ISemanticNodeProvider.INodesForEObjectProvider;
import org.eclipse.xtext.serializer.sequencer.ISemanticSequencer;
import org.eclipse.xtext.serializer.sequencer.ITransientValueService;
import org.eclipse.xtext.serializer.sequencer.ITransientValueService.ValueTransient;
import org.xtext.example.iptables.iptables.Chain;
import org.xtext.example.iptables.iptables.ChainName;
import org.xtext.example.iptables.iptables.CustomChain;
import org.xtext.example.iptables.iptables.FilterDeclaration;
import org.xtext.example.iptables.iptables.FilterSpec;
import org.xtext.example.iptables.iptables.Interface;
import org.xtext.example.iptables.iptables.IptablesPackage;
import org.xtext.example.iptables.iptables.LP;
import org.xtext.example.iptables.iptables.Match;
import org.xtext.example.iptables.iptables.Model;
import org.xtext.example.iptables.iptables.Rule;
import org.xtext.example.iptables.iptables.State;
import org.xtext.example.iptables.iptables.TCPFlag;
import org.xtext.example.iptables.services.IptablesGrammarAccess;

@SuppressWarnings("restriction")
public class AbstractIptablesSemanticSequencer extends AbstractSemanticSequencer {

	@Inject
	protected IptablesGrammarAccess grammarAccess;
	
	@Inject
	protected ISemanticSequencerDiagnosticProvider diagnosticProvider;
	
	@Inject
	protected ITransientValueService transientValues;
	
	@Inject
	@GenericSequencer
	protected Provider<ISemanticSequencer> genericSequencerProvider;
	
	protected ISemanticSequencer genericSequencer;
	
	
	@Override
	public void init(ISemanticSequencer sequencer, ISemanticSequenceAcceptor sequenceAcceptor, Acceptor errorAcceptor) {
		super.init(sequencer, sequenceAcceptor, errorAcceptor);
		this.genericSequencer = genericSequencerProvider.get();
		this.genericSequencer.init(sequencer, sequenceAcceptor, errorAcceptor);
	}
	
	public void createSequence(EObject context, EObject semanticObject) {
		if(semanticObject.eClass().getEPackage() == IptablesPackage.eINSTANCE) switch(semanticObject.eClass().getClassifierID()) {
			case IptablesPackage.CHAIN:
				if(context == grammarAccess.getChainRule()) {
					sequence_Chain(context, (Chain) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.CHAIN_NAME:
				if(context == grammarAccess.getChainDeclarationRule() ||
				   context == grammarAccess.getChainNameRule()) {
					sequence_ChainName(context, (ChainName) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.CUSTOM_CHAIN:
				if(context == grammarAccess.getCustomChainRule()) {
					sequence_CustomChain(context, (CustomChain) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.FILTER_DECLARATION:
				if(context == grammarAccess.getFilterDeclarationRule()) {
					sequence_FilterDeclaration(context, (FilterDeclaration) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.FILTER_SPEC:
				if(context == grammarAccess.getFilterSpecRule() ||
				   context == grammarAccess.getFilteringSpecRule()) {
					sequence_FilterSpec(context, (FilterSpec) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.INTERFACE:
				if(context == grammarAccess.getInterfaceRule()) {
					sequence_Interface(context, (Interface) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.LP:
				if(context == grammarAccess.getLPRule()) {
					sequence_LP(context, (LP) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.MATCH:
				if(context == grammarAccess.getMatchRule()) {
					sequence_Match(context, (Match) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.MODEL:
				if(context == grammarAccess.getModelRule()) {
					sequence_Model(context, (Model) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.RULE:
				if(context == grammarAccess.getRuleRule()) {
					sequence_Rule(context, (Rule) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.STATE:
				if(context == grammarAccess.getStateRule()) {
					sequence_State(context, (State) semanticObject); 
					return; 
				}
				else break;
			case IptablesPackage.TCP_FLAG:
				if(context == grammarAccess.getTCPFlagRule()) {
					sequence_TCPFlag(context, (TCPFlag) semanticObject); 
					return; 
				}
				else break;
			}
		if (errorAcceptor != null) errorAcceptor.accept(diagnosticProvider.createInvalidContextOrTypeDiagnostic(semanticObject, context));
	}
	
	/**
	 * Constraint:
	 *     name=ID
	 */
	protected void sequence_ChainName(EObject context, ChainName semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.CHAIN_NAME__NAME) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.CHAIN_NAME__NAME));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getChainNameAccess().getNameIDTerminalRuleCall_0(), semanticObject.getName());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     chainName=ID
	 */
	protected void sequence_Chain(EObject context, Chain semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.CHAIN__CHAIN_NAME) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.CHAIN__CHAIN_NAME));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getChainAccess().getChainNameIDTerminalRuleCall_0(), semanticObject.getChainName());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     name=[ChainName|ID]
	 */
	protected void sequence_CustomChain(EObject context, CustomChain semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.CUSTOM_CHAIN__NAME) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.CUSTOM_CHAIN__NAME));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getCustomChainAccess().getNameChainNameIDTerminalRuleCall_0_1(), semanticObject.getName());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     filter=FilteringSpec
	 */
	protected void sequence_FilterDeclaration(EObject context, FilterDeclaration semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.FILTER_DECLARATION__FILTER) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.FILTER_DECLARATION__FILTER));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getFilterDeclarationAccess().getFilterFilteringSpecParserRuleCall_0(), semanticObject.getFilter());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     (
	 *         (option='-A' | option='-D' | option='-P') 
	 *         chain=Chain 
	 *         protocol=Protocol? 
	 *         ip=IPExpr? 
	 *         interface=Interface? 
	 *         ipDst=IPExpr? 
	 *         sourcePort=INT? 
	 *         destinationPort=INT? 
	 *         neg?='!'? 
	 *         syn?='--syn'? 
	 *         matches=Match? 
	 *         (states+=State states+=State*)? 
	 *         dir=Dir? 
	 *         status=Status? 
	 *         (states+=State states+=State*)? 
	 *         (examFlags+=TCPFlag examFlags+=TCPFlag* flags+=TCPFlag flags+=TCPFlag*)? 
	 *         target=Target 
	 *         lp=LP?
	 *     )
	 */
	protected void sequence_FilterSpec(EObject context, FilterSpec semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
	
	
	/**
	 * Constraint:
	 *     name=ID
	 */
	protected void sequence_Interface(EObject context, Interface semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.INTERFACE__NAME) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.INTERFACE__NAME));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getInterfaceAccess().getNameIDTerminalRuleCall_0(), semanticObject.getName());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     name=STRING
	 */
	protected void sequence_LP(EObject context, LP semanticObject) {
		if(errorAcceptor != null) {
			if(transientValues.isValueTransient(semanticObject, IptablesPackage.Literals.LP__NAME) == ValueTransient.YES)
				errorAcceptor.accept(diagnosticProvider.createFeatureValueMissing(semanticObject, IptablesPackage.Literals.LP__NAME));
		}
		INodesForEObjectProvider nodes = createNodeProvider(semanticObject);
		SequenceFeeder feeder = createSequencerFeeder(semanticObject, nodes);
		feeder.accept(grammarAccess.getLPAccess().getNameSTRINGTerminalRuleCall_0(), semanticObject.getName());
		feeder.finish();
	}
	
	
	/**
	 * Constraint:
	 *     (name=Conntrack | name=StateMatch)
	 */
	protected void sequence_Match(EObject context, Match semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
	
	
	/**
	 * Constraint:
	 *     rules+=Rule*
	 */
	protected void sequence_Model(EObject context, Model semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
	
	
	/**
	 * Constraint:
	 *     (declaration=ChainDeclaration | filter=FilterDeclaration)
	 */
	protected void sequence_Rule(EObject context, Rule semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
	
	
	/**
	 * Constraint:
	 *     (name=NormalMatchStates | name=StateFulMatchStates)
	 */
	protected void sequence_State(EObject context, State semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
	
	
	/**
	 * Constraint:
	 *     (
	 *         name=Syn | 
	 *         name=Ack | 
	 *         name=Fin | 
	 *         name=Rst | 
	 *         name=All | 
	 *         name=None | 
	 *         name=Psh | 
	 *         name=Urg
	 *     )
	 */
	protected void sequence_TCPFlag(EObject context, TCPFlag semanticObject) {
		genericSequencer.createSequence(context, semanticObject);
	}
}
