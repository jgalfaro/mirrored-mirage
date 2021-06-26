package org.xtext.example.iptables.serializer;

import com.google.inject.Inject;
import java.util.List;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.xtext.IGrammarAccess;
import org.eclipse.xtext.RuleCall;
import org.eclipse.xtext.nodemodel.INode;
import org.eclipse.xtext.serializer.analysis.GrammarAlias.AbstractElementAlias;
import org.eclipse.xtext.serializer.analysis.GrammarAlias.TokenAlias;
import org.eclipse.xtext.serializer.analysis.ISyntacticSequencerPDAProvider.ISynNavigable;
import org.eclipse.xtext.serializer.analysis.ISyntacticSequencerPDAProvider.ISynTransition;
import org.eclipse.xtext.serializer.sequencer.AbstractSyntacticSequencer;
import org.xtext.example.iptables.services.IptablesGrammarAccess;

@SuppressWarnings("restriction")
public class AbstractIptablesSyntacticSequencer extends AbstractSyntacticSequencer {

	protected IptablesGrammarAccess grammarAccess;
	protected AbstractElementAlias match_FilterSpec_JKeyword_17_q;
	
	@Inject
	protected void init(IGrammarAccess access) {
		grammarAccess = (IptablesGrammarAccess) access;
		match_FilterSpec_JKeyword_17_q = new TokenAlias(false, true, grammarAccess.getFilterSpecAccess().getJKeyword_17());
	}
	
	@Override
	protected String getUnassignedRuleCallToken(EObject semanticObject, RuleCall ruleCall, INode node) {
		return "";
	}
	
	
	@Override
	protected void emitUnassignedTokens(EObject semanticObject, ISynTransition transition, INode fromNode, INode toNode) {
		if (transition.getAmbiguousSyntaxes().isEmpty()) return;
		List<INode> transitionNodes = collectNodes(fromNode, toNode);
		for (AbstractElementAlias syntax : transition.getAmbiguousSyntaxes()) {
			List<INode> syntaxNodes = getNodesFor(transitionNodes, syntax);
			if(match_FilterSpec_JKeyword_17_q.equals(syntax))
				emit_FilterSpec_JKeyword_17_q(semanticObject, getLastNavigableState(), syntaxNodes);
			else acceptNodes(getLastNavigableState(), syntaxNodes);
		}
	}

	/**
	 * Syntax:
	 *     '-j'?
	 */
	protected void emit_FilterSpec_JKeyword_17_q(EObject semanticObject, ISynNavigable transition, List<INode> nodes) {
		acceptNodes(transition, nodes);
	}
	
}
