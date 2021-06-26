package org.xtext.example.iptables.ui.contentassist.antlr.internal; 

import java.io.InputStream;
import org.eclipse.xtext.*;
import org.eclipse.xtext.parser.*;
import org.eclipse.xtext.parser.impl.*;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.xtext.parser.antlr.XtextTokenStream;
import org.eclipse.xtext.parser.antlr.XtextTokenStream.HiddenTokens;
import org.eclipse.xtext.ui.editor.contentassist.antlr.internal.AbstractInternalContentAssistParser;
import org.eclipse.xtext.ui.editor.contentassist.antlr.internal.DFA;
import org.xtext.example.iptables.services.IptablesGrammarAccess;



import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class InternalIptablesParser extends AbstractInternalContentAssistParser {
    public static final String[] tokenNames = new String[] {
        "<invalid>", "<EOR>", "<DOWN>", "<UP>", "RULE_ID", "RULE_INT", "RULE_STRING", "RULE_ML_COMMENT", "RULE_SL_COMMENT", "RULE_WS", "RULE_ANY_OTHER", "'conntrack'", "'State'", "'NEW'", "'NONE'", "'SYN_SENT'", "'SYN_RECV'", "'ESTABLISHED'", "'FIN_WAIT'", "'CLOSE_WAIT'", "'LAST_ACK'", "'TIME_WAIT'", "'CLOSE'", "'SYN'", "'ACK'", "'FIN'", "'RST'", "'ALL'", "'PSH'", "'URG'", "'tcp'", "'udp'", "'icmp'", "'-A'", "'-D'", "'-P'", "'iptables'", "'-j'", "'-p'", "'-s'", "'-i'", "'-d'", "'--sport'", "'--dport'", "'-m'", "'--ctstate'", "','", "'--ctdir'", "'--ctstatus'", "'--state'", "'--tcp-flags'", "'--log-prefix'", "'-N'", "'.'", "'/'", "'!'", "'--syn'"
    };
    public static final int RULE_ID=4;
    public static final int T__29=29;
    public static final int T__28=28;
    public static final int T__27=27;
    public static final int T__26=26;
    public static final int T__25=25;
    public static final int T__24=24;
    public static final int T__23=23;
    public static final int T__22=22;
    public static final int RULE_ANY_OTHER=10;
    public static final int T__21=21;
    public static final int T__20=20;
    public static final int EOF=-1;
    public static final int T__55=55;
    public static final int T__56=56;
    public static final int T__19=19;
    public static final int T__51=51;
    public static final int T__16=16;
    public static final int T__52=52;
    public static final int T__15=15;
    public static final int T__53=53;
    public static final int T__18=18;
    public static final int T__54=54;
    public static final int T__17=17;
    public static final int T__12=12;
    public static final int T__11=11;
    public static final int T__14=14;
    public static final int T__13=13;
    public static final int RULE_INT=5;
    public static final int T__50=50;
    public static final int T__42=42;
    public static final int T__43=43;
    public static final int T__40=40;
    public static final int T__41=41;
    public static final int T__46=46;
    public static final int T__47=47;
    public static final int T__44=44;
    public static final int T__45=45;
    public static final int T__48=48;
    public static final int T__49=49;
    public static final int RULE_SL_COMMENT=8;
    public static final int RULE_ML_COMMENT=7;
    public static final int T__30=30;
    public static final int T__31=31;
    public static final int RULE_STRING=6;
    public static final int T__32=32;
    public static final int T__33=33;
    public static final int T__34=34;
    public static final int T__35=35;
    public static final int T__36=36;
    public static final int T__37=37;
    public static final int T__38=38;
    public static final int T__39=39;
    public static final int RULE_WS=9;

    // delegates
    // delegators


        public InternalIptablesParser(TokenStream input) {
            this(input, new RecognizerSharedState());
        }
        public InternalIptablesParser(TokenStream input, RecognizerSharedState state) {
            super(input, state);
             
        }
        

    public String[] getTokenNames() { return InternalIptablesParser.tokenNames; }
    public String getGrammarFileName() { return "../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g"; }


     
     	private IptablesGrammarAccess grammarAccess;
     	
        public void setGrammarAccess(IptablesGrammarAccess grammarAccess) {
        	this.grammarAccess = grammarAccess;
        }
        
        @Override
        protected Grammar getGrammar() {
        	return grammarAccess.getGrammar();
        }
        
        @Override
        protected String getValueForTokenName(String tokenName) {
        	return tokenName;
        }




    // $ANTLR start "entryRuleModel"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:60:1: entryRuleModel : ruleModel EOF ;
    public final void entryRuleModel() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:61:1: ( ruleModel EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:62:1: ruleModel EOF
            {
             before(grammarAccess.getModelRule()); 
            pushFollow(FOLLOW_ruleModel_in_entryRuleModel61);
            ruleModel();

            state._fsp--;

             after(grammarAccess.getModelRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleModel68); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleModel"


    // $ANTLR start "ruleModel"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:69:1: ruleModel : ( ( rule__Model__RulesAssignment )* ) ;
    public final void ruleModel() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:73:2: ( ( ( rule__Model__RulesAssignment )* ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:74:1: ( ( rule__Model__RulesAssignment )* )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:74:1: ( ( rule__Model__RulesAssignment )* )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:75:1: ( rule__Model__RulesAssignment )*
            {
             before(grammarAccess.getModelAccess().getRulesAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:76:1: ( rule__Model__RulesAssignment )*
            loop1:
            do {
                int alt1=2;
                int LA1_0 = input.LA(1);

                if ( (LA1_0==36) ) {
                    alt1=1;
                }


                switch (alt1) {
            	case 1 :
            	    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:76:2: rule__Model__RulesAssignment
            	    {
            	    pushFollow(FOLLOW_rule__Model__RulesAssignment_in_ruleModel94);
            	    rule__Model__RulesAssignment();

            	    state._fsp--;


            	    }
            	    break;

            	default :
            	    break loop1;
                }
            } while (true);

             after(grammarAccess.getModelAccess().getRulesAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleModel"


    // $ANTLR start "entryRuleRule"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:88:1: entryRuleRule : ruleRule EOF ;
    public final void entryRuleRule() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:89:1: ( ruleRule EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:90:1: ruleRule EOF
            {
             before(grammarAccess.getRuleRule()); 
            pushFollow(FOLLOW_ruleRule_in_entryRuleRule122);
            ruleRule();

            state._fsp--;

             after(grammarAccess.getRuleRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleRule129); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleRule"


    // $ANTLR start "ruleRule"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:97:1: ruleRule : ( ( rule__Rule__Alternatives ) ) ;
    public final void ruleRule() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:101:2: ( ( ( rule__Rule__Alternatives ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:102:1: ( ( rule__Rule__Alternatives ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:102:1: ( ( rule__Rule__Alternatives ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:103:1: ( rule__Rule__Alternatives )
            {
             before(grammarAccess.getRuleAccess().getAlternatives()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:104:1: ( rule__Rule__Alternatives )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:104:2: rule__Rule__Alternatives
            {
            pushFollow(FOLLOW_rule__Rule__Alternatives_in_ruleRule155);
            rule__Rule__Alternatives();

            state._fsp--;


            }

             after(grammarAccess.getRuleAccess().getAlternatives()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleRule"


    // $ANTLR start "entryRuleFilterDeclaration"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:116:1: entryRuleFilterDeclaration : ruleFilterDeclaration EOF ;
    public final void entryRuleFilterDeclaration() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:117:1: ( ruleFilterDeclaration EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:118:1: ruleFilterDeclaration EOF
            {
             before(grammarAccess.getFilterDeclarationRule()); 
            pushFollow(FOLLOW_ruleFilterDeclaration_in_entryRuleFilterDeclaration182);
            ruleFilterDeclaration();

            state._fsp--;

             after(grammarAccess.getFilterDeclarationRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleFilterDeclaration189); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleFilterDeclaration"


    // $ANTLR start "ruleFilterDeclaration"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:125:1: ruleFilterDeclaration : ( ( rule__FilterDeclaration__FilterAssignment ) ) ;
    public final void ruleFilterDeclaration() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:129:2: ( ( ( rule__FilterDeclaration__FilterAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:130:1: ( ( rule__FilterDeclaration__FilterAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:130:1: ( ( rule__FilterDeclaration__FilterAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:131:1: ( rule__FilterDeclaration__FilterAssignment )
            {
             before(grammarAccess.getFilterDeclarationAccess().getFilterAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:132:1: ( rule__FilterDeclaration__FilterAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:132:2: rule__FilterDeclaration__FilterAssignment
            {
            pushFollow(FOLLOW_rule__FilterDeclaration__FilterAssignment_in_ruleFilterDeclaration215);
            rule__FilterDeclaration__FilterAssignment();

            state._fsp--;


            }

             after(grammarAccess.getFilterDeclarationAccess().getFilterAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleFilterDeclaration"


    // $ANTLR start "entryRuleFilteringSpec"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:144:1: entryRuleFilteringSpec : ruleFilteringSpec EOF ;
    public final void entryRuleFilteringSpec() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:145:1: ( ruleFilteringSpec EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:146:1: ruleFilteringSpec EOF
            {
             before(grammarAccess.getFilteringSpecRule()); 
            pushFollow(FOLLOW_ruleFilteringSpec_in_entryRuleFilteringSpec242);
            ruleFilteringSpec();

            state._fsp--;

             after(grammarAccess.getFilteringSpecRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleFilteringSpec249); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleFilteringSpec"


    // $ANTLR start "ruleFilteringSpec"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:153:1: ruleFilteringSpec : ( ruleFilterSpec ) ;
    public final void ruleFilteringSpec() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:157:2: ( ( ruleFilterSpec ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:158:1: ( ruleFilterSpec )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:158:1: ( ruleFilterSpec )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:159:1: ruleFilterSpec
            {
             before(grammarAccess.getFilteringSpecAccess().getFilterSpecParserRuleCall()); 
            pushFollow(FOLLOW_ruleFilterSpec_in_ruleFilteringSpec275);
            ruleFilterSpec();

            state._fsp--;

             after(grammarAccess.getFilteringSpecAccess().getFilterSpecParserRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleFilteringSpec"


    // $ANTLR start "entryRuleFilterSpec"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:172:1: entryRuleFilterSpec : ruleFilterSpec EOF ;
    public final void entryRuleFilterSpec() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:173:1: ( ruleFilterSpec EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:174:1: ruleFilterSpec EOF
            {
             before(grammarAccess.getFilterSpecRule()); 
            pushFollow(FOLLOW_ruleFilterSpec_in_entryRuleFilterSpec301);
            ruleFilterSpec();

            state._fsp--;

             after(grammarAccess.getFilterSpecRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleFilterSpec308); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleFilterSpec"


    // $ANTLR start "ruleFilterSpec"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:181:1: ruleFilterSpec : ( ( rule__FilterSpec__Group__0 ) ) ;
    public final void ruleFilterSpec() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:185:2: ( ( ( rule__FilterSpec__Group__0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:186:1: ( ( rule__FilterSpec__Group__0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:186:1: ( ( rule__FilterSpec__Group__0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:187:1: ( rule__FilterSpec__Group__0 )
            {
             before(grammarAccess.getFilterSpecAccess().getGroup()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:188:1: ( rule__FilterSpec__Group__0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:188:2: rule__FilterSpec__Group__0
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__0_in_ruleFilterSpec334);
            rule__FilterSpec__Group__0();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getGroup()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleFilterSpec"


    // $ANTLR start "entryRuleInterface"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:200:1: entryRuleInterface : ruleInterface EOF ;
    public final void entryRuleInterface() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:201:1: ( ruleInterface EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:202:1: ruleInterface EOF
            {
             before(grammarAccess.getInterfaceRule()); 
            pushFollow(FOLLOW_ruleInterface_in_entryRuleInterface361);
            ruleInterface();

            state._fsp--;

             after(grammarAccess.getInterfaceRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleInterface368); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleInterface"


    // $ANTLR start "ruleInterface"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:209:1: ruleInterface : ( ( rule__Interface__NameAssignment ) ) ;
    public final void ruleInterface() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:213:2: ( ( ( rule__Interface__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:214:1: ( ( rule__Interface__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:214:1: ( ( rule__Interface__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:215:1: ( rule__Interface__NameAssignment )
            {
             before(grammarAccess.getInterfaceAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:216:1: ( rule__Interface__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:216:2: rule__Interface__NameAssignment
            {
            pushFollow(FOLLOW_rule__Interface__NameAssignment_in_ruleInterface394);
            rule__Interface__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getInterfaceAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleInterface"


    // $ANTLR start "entryRuleLP"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:228:1: entryRuleLP : ruleLP EOF ;
    public final void entryRuleLP() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:229:1: ( ruleLP EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:230:1: ruleLP EOF
            {
             before(grammarAccess.getLPRule()); 
            pushFollow(FOLLOW_ruleLP_in_entryRuleLP421);
            ruleLP();

            state._fsp--;

             after(grammarAccess.getLPRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleLP428); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleLP"


    // $ANTLR start "ruleLP"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:237:1: ruleLP : ( ( rule__LP__NameAssignment ) ) ;
    public final void ruleLP() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:241:2: ( ( ( rule__LP__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:242:1: ( ( rule__LP__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:242:1: ( ( rule__LP__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:243:1: ( rule__LP__NameAssignment )
            {
             before(grammarAccess.getLPAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:244:1: ( rule__LP__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:244:2: rule__LP__NameAssignment
            {
            pushFollow(FOLLOW_rule__LP__NameAssignment_in_ruleLP454);
            rule__LP__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getLPAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleLP"


    // $ANTLR start "entryRuleMatch"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:256:1: entryRuleMatch : ruleMatch EOF ;
    public final void entryRuleMatch() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:257:1: ( ruleMatch EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:258:1: ruleMatch EOF
            {
             before(grammarAccess.getMatchRule()); 
            pushFollow(FOLLOW_ruleMatch_in_entryRuleMatch481);
            ruleMatch();

            state._fsp--;

             after(grammarAccess.getMatchRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleMatch488); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleMatch"


    // $ANTLR start "ruleMatch"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:265:1: ruleMatch : ( ( rule__Match__NameAssignment ) ) ;
    public final void ruleMatch() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:269:2: ( ( ( rule__Match__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:270:1: ( ( rule__Match__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:270:1: ( ( rule__Match__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:271:1: ( rule__Match__NameAssignment )
            {
             before(grammarAccess.getMatchAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:272:1: ( rule__Match__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:272:2: rule__Match__NameAssignment
            {
            pushFollow(FOLLOW_rule__Match__NameAssignment_in_ruleMatch514);
            rule__Match__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getMatchAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleMatch"


    // $ANTLR start "entryRuleDir"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:284:1: entryRuleDir : ruleDir EOF ;
    public final void entryRuleDir() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:285:1: ( ruleDir EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:286:1: ruleDir EOF
            {
             before(grammarAccess.getDirRule()); 
            pushFollow(FOLLOW_ruleDir_in_entryRuleDir541);
            ruleDir();

            state._fsp--;

             after(grammarAccess.getDirRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleDir548); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleDir"


    // $ANTLR start "ruleDir"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:293:1: ruleDir : ( RULE_ID ) ;
    public final void ruleDir() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:297:2: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:298:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:298:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:299:1: RULE_ID
            {
             before(grammarAccess.getDirAccess().getIDTerminalRuleCall()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_ruleDir574); 
             after(grammarAccess.getDirAccess().getIDTerminalRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleDir"


    // $ANTLR start "entryRuleStatus"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:312:1: entryRuleStatus : ruleStatus EOF ;
    public final void entryRuleStatus() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:313:1: ( ruleStatus EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:314:1: ruleStatus EOF
            {
             before(grammarAccess.getStatusRule()); 
            pushFollow(FOLLOW_ruleStatus_in_entryRuleStatus600);
            ruleStatus();

            state._fsp--;

             after(grammarAccess.getStatusRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleStatus607); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleStatus"


    // $ANTLR start "ruleStatus"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:321:1: ruleStatus : ( RULE_ID ) ;
    public final void ruleStatus() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:325:2: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:326:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:326:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:327:1: RULE_ID
            {
             before(grammarAccess.getStatusAccess().getIDTerminalRuleCall()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_ruleStatus633); 
             after(grammarAccess.getStatusAccess().getIDTerminalRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleStatus"


    // $ANTLR start "entryRuleConntrack"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:340:1: entryRuleConntrack : ruleConntrack EOF ;
    public final void entryRuleConntrack() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:341:1: ( ruleConntrack EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:342:1: ruleConntrack EOF
            {
             before(grammarAccess.getConntrackRule()); 
            pushFollow(FOLLOW_ruleConntrack_in_entryRuleConntrack659);
            ruleConntrack();

            state._fsp--;

             after(grammarAccess.getConntrackRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleConntrack666); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleConntrack"


    // $ANTLR start "ruleConntrack"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:349:1: ruleConntrack : ( 'conntrack' ) ;
    public final void ruleConntrack() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:353:2: ( ( 'conntrack' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:354:1: ( 'conntrack' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:354:1: ( 'conntrack' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:355:1: 'conntrack'
            {
             before(grammarAccess.getConntrackAccess().getConntrackKeyword()); 
            match(input,11,FOLLOW_11_in_ruleConntrack693); 
             after(grammarAccess.getConntrackAccess().getConntrackKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleConntrack"


    // $ANTLR start "entryRuleStateMatch"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:370:1: entryRuleStateMatch : ruleStateMatch EOF ;
    public final void entryRuleStateMatch() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:371:1: ( ruleStateMatch EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:372:1: ruleStateMatch EOF
            {
             before(grammarAccess.getStateMatchRule()); 
            pushFollow(FOLLOW_ruleStateMatch_in_entryRuleStateMatch721);
            ruleStateMatch();

            state._fsp--;

             after(grammarAccess.getStateMatchRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleStateMatch728); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleStateMatch"


    // $ANTLR start "ruleStateMatch"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:379:1: ruleStateMatch : ( 'State' ) ;
    public final void ruleStateMatch() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:383:2: ( ( 'State' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:384:1: ( 'State' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:384:1: ( 'State' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:385:1: 'State'
            {
             before(grammarAccess.getStateMatchAccess().getStateKeyword()); 
            match(input,12,FOLLOW_12_in_ruleStateMatch755); 
             after(grammarAccess.getStateMatchAccess().getStateKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleStateMatch"


    // $ANTLR start "entryRuleState"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:400:1: entryRuleState : ruleState EOF ;
    public final void entryRuleState() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:401:1: ( ruleState EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:402:1: ruleState EOF
            {
             before(grammarAccess.getStateRule()); 
            pushFollow(FOLLOW_ruleState_in_entryRuleState783);
            ruleState();

            state._fsp--;

             after(grammarAccess.getStateRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleState790); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleState"


    // $ANTLR start "ruleState"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:409:1: ruleState : ( ( rule__State__NameAssignment ) ) ;
    public final void ruleState() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:413:2: ( ( ( rule__State__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:414:1: ( ( rule__State__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:414:1: ( ( rule__State__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:415:1: ( rule__State__NameAssignment )
            {
             before(grammarAccess.getStateAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:416:1: ( rule__State__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:416:2: rule__State__NameAssignment
            {
            pushFollow(FOLLOW_rule__State__NameAssignment_in_ruleState816);
            rule__State__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getStateAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleState"


    // $ANTLR start "entryRuleStateFulMatchStates"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:428:1: entryRuleStateFulMatchStates : ruleStateFulMatchStates EOF ;
    public final void entryRuleStateFulMatchStates() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:429:1: ( ruleStateFulMatchStates EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:430:1: ruleStateFulMatchStates EOF
            {
             before(grammarAccess.getStateFulMatchStatesRule()); 
            pushFollow(FOLLOW_ruleStateFulMatchStates_in_entryRuleStateFulMatchStates843);
            ruleStateFulMatchStates();

            state._fsp--;

             after(grammarAccess.getStateFulMatchStatesRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleStateFulMatchStates850); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleStateFulMatchStates"


    // $ANTLR start "ruleStateFulMatchStates"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:437:1: ruleStateFulMatchStates : ( ( rule__StateFulMatchStates__Alternatives ) ) ;
    public final void ruleStateFulMatchStates() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:441:2: ( ( ( rule__StateFulMatchStates__Alternatives ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:442:1: ( ( rule__StateFulMatchStates__Alternatives ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:442:1: ( ( rule__StateFulMatchStates__Alternatives ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:443:1: ( rule__StateFulMatchStates__Alternatives )
            {
             before(grammarAccess.getStateFulMatchStatesAccess().getAlternatives()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:444:1: ( rule__StateFulMatchStates__Alternatives )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:444:2: rule__StateFulMatchStates__Alternatives
            {
            pushFollow(FOLLOW_rule__StateFulMatchStates__Alternatives_in_ruleStateFulMatchStates876);
            rule__StateFulMatchStates__Alternatives();

            state._fsp--;


            }

             after(grammarAccess.getStateFulMatchStatesAccess().getAlternatives()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleStateFulMatchStates"


    // $ANTLR start "entryRuleNormalMatchStates"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:456:1: entryRuleNormalMatchStates : ruleNormalMatchStates EOF ;
    public final void entryRuleNormalMatchStates() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:457:1: ( ruleNormalMatchStates EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:458:1: ruleNormalMatchStates EOF
            {
             before(grammarAccess.getNormalMatchStatesRule()); 
            pushFollow(FOLLOW_ruleNormalMatchStates_in_entryRuleNormalMatchStates903);
            ruleNormalMatchStates();

            state._fsp--;

             after(grammarAccess.getNormalMatchStatesRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleNormalMatchStates910); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleNormalMatchStates"


    // $ANTLR start "ruleNormalMatchStates"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:465:1: ruleNormalMatchStates : ( ruleNew ) ;
    public final void ruleNormalMatchStates() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:469:2: ( ( ruleNew ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:470:1: ( ruleNew )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:470:1: ( ruleNew )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:471:1: ruleNew
            {
             before(grammarAccess.getNormalMatchStatesAccess().getNewParserRuleCall()); 
            pushFollow(FOLLOW_ruleNew_in_ruleNormalMatchStates936);
            ruleNew();

            state._fsp--;

             after(grammarAccess.getNormalMatchStatesAccess().getNewParserRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleNormalMatchStates"


    // $ANTLR start "entryRuleNew"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:484:1: entryRuleNew : ruleNew EOF ;
    public final void entryRuleNew() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:485:1: ( ruleNew EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:486:1: ruleNew EOF
            {
             before(grammarAccess.getNewRule()); 
            pushFollow(FOLLOW_ruleNew_in_entryRuleNew962);
            ruleNew();

            state._fsp--;

             after(grammarAccess.getNewRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleNew969); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleNew"


    // $ANTLR start "ruleNew"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:493:1: ruleNew : ( 'NEW' ) ;
    public final void ruleNew() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:497:2: ( ( 'NEW' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:498:1: ( 'NEW' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:498:1: ( 'NEW' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:499:1: 'NEW'
            {
             before(grammarAccess.getNewAccess().getNEWKeyword()); 
            match(input,13,FOLLOW_13_in_ruleNew996); 
             after(grammarAccess.getNewAccess().getNEWKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleNew"


    // $ANTLR start "entryRuleNoneS"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:514:1: entryRuleNoneS : ruleNoneS EOF ;
    public final void entryRuleNoneS() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:515:1: ( ruleNoneS EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:516:1: ruleNoneS EOF
            {
             before(grammarAccess.getNoneSRule()); 
            pushFollow(FOLLOW_ruleNoneS_in_entryRuleNoneS1024);
            ruleNoneS();

            state._fsp--;

             after(grammarAccess.getNoneSRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleNoneS1031); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleNoneS"


    // $ANTLR start "ruleNoneS"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:523:1: ruleNoneS : ( 'NONE' ) ;
    public final void ruleNoneS() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:527:2: ( ( 'NONE' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:528:1: ( 'NONE' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:528:1: ( 'NONE' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:529:1: 'NONE'
            {
             before(grammarAccess.getNoneSAccess().getNONEKeyword()); 
            match(input,14,FOLLOW_14_in_ruleNoneS1058); 
             after(grammarAccess.getNoneSAccess().getNONEKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleNoneS"


    // $ANTLR start "entryRuleSynSent"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:544:1: entryRuleSynSent : ruleSynSent EOF ;
    public final void entryRuleSynSent() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:545:1: ( ruleSynSent EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:546:1: ruleSynSent EOF
            {
             before(grammarAccess.getSynSentRule()); 
            pushFollow(FOLLOW_ruleSynSent_in_entryRuleSynSent1086);
            ruleSynSent();

            state._fsp--;

             after(grammarAccess.getSynSentRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleSynSent1093); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleSynSent"


    // $ANTLR start "ruleSynSent"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:553:1: ruleSynSent : ( 'SYN_SENT' ) ;
    public final void ruleSynSent() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:557:2: ( ( 'SYN_SENT' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:558:1: ( 'SYN_SENT' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:558:1: ( 'SYN_SENT' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:559:1: 'SYN_SENT'
            {
             before(grammarAccess.getSynSentAccess().getSYN_SENTKeyword()); 
            match(input,15,FOLLOW_15_in_ruleSynSent1120); 
             after(grammarAccess.getSynSentAccess().getSYN_SENTKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleSynSent"


    // $ANTLR start "entryRuleSynRecv"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:574:1: entryRuleSynRecv : ruleSynRecv EOF ;
    public final void entryRuleSynRecv() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:575:1: ( ruleSynRecv EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:576:1: ruleSynRecv EOF
            {
             before(grammarAccess.getSynRecvRule()); 
            pushFollow(FOLLOW_ruleSynRecv_in_entryRuleSynRecv1148);
            ruleSynRecv();

            state._fsp--;

             after(grammarAccess.getSynRecvRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleSynRecv1155); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleSynRecv"


    // $ANTLR start "ruleSynRecv"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:583:1: ruleSynRecv : ( 'SYN_RECV' ) ;
    public final void ruleSynRecv() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:587:2: ( ( 'SYN_RECV' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:588:1: ( 'SYN_RECV' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:588:1: ( 'SYN_RECV' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:589:1: 'SYN_RECV'
            {
             before(grammarAccess.getSynRecvAccess().getSYN_RECVKeyword()); 
            match(input,16,FOLLOW_16_in_ruleSynRecv1182); 
             after(grammarAccess.getSynRecvAccess().getSYN_RECVKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleSynRecv"


    // $ANTLR start "entryRuleEstablished"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:604:1: entryRuleEstablished : ruleEstablished EOF ;
    public final void entryRuleEstablished() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:605:1: ( ruleEstablished EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:606:1: ruleEstablished EOF
            {
             before(grammarAccess.getEstablishedRule()); 
            pushFollow(FOLLOW_ruleEstablished_in_entryRuleEstablished1210);
            ruleEstablished();

            state._fsp--;

             after(grammarAccess.getEstablishedRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleEstablished1217); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleEstablished"


    // $ANTLR start "ruleEstablished"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:613:1: ruleEstablished : ( 'ESTABLISHED' ) ;
    public final void ruleEstablished() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:617:2: ( ( 'ESTABLISHED' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:618:1: ( 'ESTABLISHED' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:618:1: ( 'ESTABLISHED' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:619:1: 'ESTABLISHED'
            {
             before(grammarAccess.getEstablishedAccess().getESTABLISHEDKeyword()); 
            match(input,17,FOLLOW_17_in_ruleEstablished1244); 
             after(grammarAccess.getEstablishedAccess().getESTABLISHEDKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleEstablished"


    // $ANTLR start "entryRuleFinWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:634:1: entryRuleFinWait : ruleFinWait EOF ;
    public final void entryRuleFinWait() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:635:1: ( ruleFinWait EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:636:1: ruleFinWait EOF
            {
             before(grammarAccess.getFinWaitRule()); 
            pushFollow(FOLLOW_ruleFinWait_in_entryRuleFinWait1272);
            ruleFinWait();

            state._fsp--;

             after(grammarAccess.getFinWaitRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleFinWait1279); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleFinWait"


    // $ANTLR start "ruleFinWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:643:1: ruleFinWait : ( 'FIN_WAIT' ) ;
    public final void ruleFinWait() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:647:2: ( ( 'FIN_WAIT' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:648:1: ( 'FIN_WAIT' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:648:1: ( 'FIN_WAIT' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:649:1: 'FIN_WAIT'
            {
             before(grammarAccess.getFinWaitAccess().getFIN_WAITKeyword()); 
            match(input,18,FOLLOW_18_in_ruleFinWait1306); 
             after(grammarAccess.getFinWaitAccess().getFIN_WAITKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleFinWait"


    // $ANTLR start "entryRuleCloseWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:664:1: entryRuleCloseWait : ruleCloseWait EOF ;
    public final void entryRuleCloseWait() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:665:1: ( ruleCloseWait EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:666:1: ruleCloseWait EOF
            {
             before(grammarAccess.getCloseWaitRule()); 
            pushFollow(FOLLOW_ruleCloseWait_in_entryRuleCloseWait1334);
            ruleCloseWait();

            state._fsp--;

             after(grammarAccess.getCloseWaitRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleCloseWait1341); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleCloseWait"


    // $ANTLR start "ruleCloseWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:673:1: ruleCloseWait : ( 'CLOSE_WAIT' ) ;
    public final void ruleCloseWait() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:677:2: ( ( 'CLOSE_WAIT' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:678:1: ( 'CLOSE_WAIT' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:678:1: ( 'CLOSE_WAIT' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:679:1: 'CLOSE_WAIT'
            {
             before(grammarAccess.getCloseWaitAccess().getCLOSE_WAITKeyword()); 
            match(input,19,FOLLOW_19_in_ruleCloseWait1368); 
             after(grammarAccess.getCloseWaitAccess().getCLOSE_WAITKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleCloseWait"


    // $ANTLR start "entryRuleLastAck"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:694:1: entryRuleLastAck : ruleLastAck EOF ;
    public final void entryRuleLastAck() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:695:1: ( ruleLastAck EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:696:1: ruleLastAck EOF
            {
             before(grammarAccess.getLastAckRule()); 
            pushFollow(FOLLOW_ruleLastAck_in_entryRuleLastAck1396);
            ruleLastAck();

            state._fsp--;

             after(grammarAccess.getLastAckRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleLastAck1403); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleLastAck"


    // $ANTLR start "ruleLastAck"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:703:1: ruleLastAck : ( 'LAST_ACK' ) ;
    public final void ruleLastAck() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:707:2: ( ( 'LAST_ACK' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:708:1: ( 'LAST_ACK' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:708:1: ( 'LAST_ACK' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:709:1: 'LAST_ACK'
            {
             before(grammarAccess.getLastAckAccess().getLAST_ACKKeyword()); 
            match(input,20,FOLLOW_20_in_ruleLastAck1430); 
             after(grammarAccess.getLastAckAccess().getLAST_ACKKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleLastAck"


    // $ANTLR start "entryRuleTimeWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:724:1: entryRuleTimeWait : ruleTimeWait EOF ;
    public final void entryRuleTimeWait() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:725:1: ( ruleTimeWait EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:726:1: ruleTimeWait EOF
            {
             before(grammarAccess.getTimeWaitRule()); 
            pushFollow(FOLLOW_ruleTimeWait_in_entryRuleTimeWait1458);
            ruleTimeWait();

            state._fsp--;

             after(grammarAccess.getTimeWaitRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleTimeWait1465); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleTimeWait"


    // $ANTLR start "ruleTimeWait"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:733:1: ruleTimeWait : ( 'TIME_WAIT' ) ;
    public final void ruleTimeWait() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:737:2: ( ( 'TIME_WAIT' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:738:1: ( 'TIME_WAIT' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:738:1: ( 'TIME_WAIT' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:739:1: 'TIME_WAIT'
            {
             before(grammarAccess.getTimeWaitAccess().getTIME_WAITKeyword()); 
            match(input,21,FOLLOW_21_in_ruleTimeWait1492); 
             after(grammarAccess.getTimeWaitAccess().getTIME_WAITKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleTimeWait"


    // $ANTLR start "entryRuleClose"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:754:1: entryRuleClose : ruleClose EOF ;
    public final void entryRuleClose() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:755:1: ( ruleClose EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:756:1: ruleClose EOF
            {
             before(grammarAccess.getCloseRule()); 
            pushFollow(FOLLOW_ruleClose_in_entryRuleClose1520);
            ruleClose();

            state._fsp--;

             after(grammarAccess.getCloseRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleClose1527); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleClose"


    // $ANTLR start "ruleClose"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:763:1: ruleClose : ( 'CLOSE' ) ;
    public final void ruleClose() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:767:2: ( ( 'CLOSE' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:768:1: ( 'CLOSE' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:768:1: ( 'CLOSE' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:769:1: 'CLOSE'
            {
             before(grammarAccess.getCloseAccess().getCLOSEKeyword()); 
            match(input,22,FOLLOW_22_in_ruleClose1554); 
             after(grammarAccess.getCloseAccess().getCLOSEKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleClose"


    // $ANTLR start "entryRuleTCPFlag"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:784:1: entryRuleTCPFlag : ruleTCPFlag EOF ;
    public final void entryRuleTCPFlag() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:785:1: ( ruleTCPFlag EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:786:1: ruleTCPFlag EOF
            {
             before(grammarAccess.getTCPFlagRule()); 
            pushFollow(FOLLOW_ruleTCPFlag_in_entryRuleTCPFlag1582);
            ruleTCPFlag();

            state._fsp--;

             after(grammarAccess.getTCPFlagRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleTCPFlag1589); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleTCPFlag"


    // $ANTLR start "ruleTCPFlag"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:793:1: ruleTCPFlag : ( ( rule__TCPFlag__NameAssignment ) ) ;
    public final void ruleTCPFlag() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:797:2: ( ( ( rule__TCPFlag__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:798:1: ( ( rule__TCPFlag__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:798:1: ( ( rule__TCPFlag__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:799:1: ( rule__TCPFlag__NameAssignment )
            {
             before(grammarAccess.getTCPFlagAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:800:1: ( rule__TCPFlag__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:800:2: rule__TCPFlag__NameAssignment
            {
            pushFollow(FOLLOW_rule__TCPFlag__NameAssignment_in_ruleTCPFlag1615);
            rule__TCPFlag__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getTCPFlagAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleTCPFlag"


    // $ANTLR start "entryRuleSyn"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:812:1: entryRuleSyn : ruleSyn EOF ;
    public final void entryRuleSyn() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:813:1: ( ruleSyn EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:814:1: ruleSyn EOF
            {
             before(grammarAccess.getSynRule()); 
            pushFollow(FOLLOW_ruleSyn_in_entryRuleSyn1642);
            ruleSyn();

            state._fsp--;

             after(grammarAccess.getSynRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleSyn1649); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleSyn"


    // $ANTLR start "ruleSyn"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:821:1: ruleSyn : ( 'SYN' ) ;
    public final void ruleSyn() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:825:2: ( ( 'SYN' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:826:1: ( 'SYN' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:826:1: ( 'SYN' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:827:1: 'SYN'
            {
             before(grammarAccess.getSynAccess().getSYNKeyword()); 
            match(input,23,FOLLOW_23_in_ruleSyn1676); 
             after(grammarAccess.getSynAccess().getSYNKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleSyn"


    // $ANTLR start "entryRuleAck"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:842:1: entryRuleAck : ruleAck EOF ;
    public final void entryRuleAck() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:843:1: ( ruleAck EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:844:1: ruleAck EOF
            {
             before(grammarAccess.getAckRule()); 
            pushFollow(FOLLOW_ruleAck_in_entryRuleAck1704);
            ruleAck();

            state._fsp--;

             after(grammarAccess.getAckRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleAck1711); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleAck"


    // $ANTLR start "ruleAck"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:851:1: ruleAck : ( 'ACK' ) ;
    public final void ruleAck() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:855:2: ( ( 'ACK' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:856:1: ( 'ACK' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:856:1: ( 'ACK' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:857:1: 'ACK'
            {
             before(grammarAccess.getAckAccess().getACKKeyword()); 
            match(input,24,FOLLOW_24_in_ruleAck1738); 
             after(grammarAccess.getAckAccess().getACKKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleAck"


    // $ANTLR start "entryRuleFin"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:872:1: entryRuleFin : ruleFin EOF ;
    public final void entryRuleFin() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:873:1: ( ruleFin EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:874:1: ruleFin EOF
            {
             before(grammarAccess.getFinRule()); 
            pushFollow(FOLLOW_ruleFin_in_entryRuleFin1766);
            ruleFin();

            state._fsp--;

             after(grammarAccess.getFinRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleFin1773); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleFin"


    // $ANTLR start "ruleFin"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:881:1: ruleFin : ( 'FIN' ) ;
    public final void ruleFin() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:885:2: ( ( 'FIN' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:886:1: ( 'FIN' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:886:1: ( 'FIN' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:887:1: 'FIN'
            {
             before(grammarAccess.getFinAccess().getFINKeyword()); 
            match(input,25,FOLLOW_25_in_ruleFin1800); 
             after(grammarAccess.getFinAccess().getFINKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleFin"


    // $ANTLR start "entryRuleRst"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:902:1: entryRuleRst : ruleRst EOF ;
    public final void entryRuleRst() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:903:1: ( ruleRst EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:904:1: ruleRst EOF
            {
             before(grammarAccess.getRstRule()); 
            pushFollow(FOLLOW_ruleRst_in_entryRuleRst1828);
            ruleRst();

            state._fsp--;

             after(grammarAccess.getRstRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleRst1835); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleRst"


    // $ANTLR start "ruleRst"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:911:1: ruleRst : ( 'RST' ) ;
    public final void ruleRst() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:915:2: ( ( 'RST' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:916:1: ( 'RST' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:916:1: ( 'RST' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:917:1: 'RST'
            {
             before(grammarAccess.getRstAccess().getRSTKeyword()); 
            match(input,26,FOLLOW_26_in_ruleRst1862); 
             after(grammarAccess.getRstAccess().getRSTKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleRst"


    // $ANTLR start "entryRuleAll"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:932:1: entryRuleAll : ruleAll EOF ;
    public final void entryRuleAll() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:933:1: ( ruleAll EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:934:1: ruleAll EOF
            {
             before(grammarAccess.getAllRule()); 
            pushFollow(FOLLOW_ruleAll_in_entryRuleAll1890);
            ruleAll();

            state._fsp--;

             after(grammarAccess.getAllRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleAll1897); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleAll"


    // $ANTLR start "ruleAll"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:941:1: ruleAll : ( 'ALL' ) ;
    public final void ruleAll() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:945:2: ( ( 'ALL' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:946:1: ( 'ALL' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:946:1: ( 'ALL' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:947:1: 'ALL'
            {
             before(grammarAccess.getAllAccess().getALLKeyword()); 
            match(input,27,FOLLOW_27_in_ruleAll1924); 
             after(grammarAccess.getAllAccess().getALLKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleAll"


    // $ANTLR start "entryRuleNone"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:962:1: entryRuleNone : ruleNone EOF ;
    public final void entryRuleNone() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:963:1: ( ruleNone EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:964:1: ruleNone EOF
            {
             before(grammarAccess.getNoneRule()); 
            pushFollow(FOLLOW_ruleNone_in_entryRuleNone1952);
            ruleNone();

            state._fsp--;

             after(grammarAccess.getNoneRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleNone1959); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleNone"


    // $ANTLR start "ruleNone"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:971:1: ruleNone : ( 'NONE' ) ;
    public final void ruleNone() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:975:2: ( ( 'NONE' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:976:1: ( 'NONE' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:976:1: ( 'NONE' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:977:1: 'NONE'
            {
             before(grammarAccess.getNoneAccess().getNONEKeyword()); 
            match(input,14,FOLLOW_14_in_ruleNone1986); 
             after(grammarAccess.getNoneAccess().getNONEKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleNone"


    // $ANTLR start "entryRulePsh"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:992:1: entryRulePsh : rulePsh EOF ;
    public final void entryRulePsh() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:993:1: ( rulePsh EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:994:1: rulePsh EOF
            {
             before(grammarAccess.getPshRule()); 
            pushFollow(FOLLOW_rulePsh_in_entryRulePsh2014);
            rulePsh();

            state._fsp--;

             after(grammarAccess.getPshRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRulePsh2021); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRulePsh"


    // $ANTLR start "rulePsh"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1001:1: rulePsh : ( 'PSH' ) ;
    public final void rulePsh() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1005:2: ( ( 'PSH' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1006:1: ( 'PSH' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1006:1: ( 'PSH' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1007:1: 'PSH'
            {
             before(grammarAccess.getPshAccess().getPSHKeyword()); 
            match(input,28,FOLLOW_28_in_rulePsh2048); 
             after(grammarAccess.getPshAccess().getPSHKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rulePsh"


    // $ANTLR start "entryRuleUrg"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1022:1: entryRuleUrg : ruleUrg EOF ;
    public final void entryRuleUrg() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1023:1: ( ruleUrg EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1024:1: ruleUrg EOF
            {
             before(grammarAccess.getUrgRule()); 
            pushFollow(FOLLOW_ruleUrg_in_entryRuleUrg2076);
            ruleUrg();

            state._fsp--;

             after(grammarAccess.getUrgRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleUrg2083); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleUrg"


    // $ANTLR start "ruleUrg"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1031:1: ruleUrg : ( 'URG' ) ;
    public final void ruleUrg() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1035:2: ( ( 'URG' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1036:1: ( 'URG' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1036:1: ( 'URG' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1037:1: 'URG'
            {
             before(grammarAccess.getUrgAccess().getURGKeyword()); 
            match(input,29,FOLLOW_29_in_ruleUrg2110); 
             after(grammarAccess.getUrgAccess().getURGKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleUrg"


    // $ANTLR start "entryRuleProtocol"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1052:1: entryRuleProtocol : ruleProtocol EOF ;
    public final void entryRuleProtocol() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1053:1: ( ruleProtocol EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1054:1: ruleProtocol EOF
            {
             before(grammarAccess.getProtocolRule()); 
            pushFollow(FOLLOW_ruleProtocol_in_entryRuleProtocol2138);
            ruleProtocol();

            state._fsp--;

             after(grammarAccess.getProtocolRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleProtocol2145); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleProtocol"


    // $ANTLR start "ruleProtocol"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1061:1: ruleProtocol : ( ( rule__Protocol__Alternatives ) ) ;
    public final void ruleProtocol() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1065:2: ( ( ( rule__Protocol__Alternatives ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1066:1: ( ( rule__Protocol__Alternatives ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1066:1: ( ( rule__Protocol__Alternatives ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1067:1: ( rule__Protocol__Alternatives )
            {
             before(grammarAccess.getProtocolAccess().getAlternatives()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1068:1: ( rule__Protocol__Alternatives )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1068:2: rule__Protocol__Alternatives
            {
            pushFollow(FOLLOW_rule__Protocol__Alternatives_in_ruleProtocol2171);
            rule__Protocol__Alternatives();

            state._fsp--;


            }

             after(grammarAccess.getProtocolAccess().getAlternatives()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleProtocol"


    // $ANTLR start "entryRuleTcp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1080:1: entryRuleTcp : ruleTcp EOF ;
    public final void entryRuleTcp() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1081:1: ( ruleTcp EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1082:1: ruleTcp EOF
            {
             before(grammarAccess.getTcpRule()); 
            pushFollow(FOLLOW_ruleTcp_in_entryRuleTcp2198);
            ruleTcp();

            state._fsp--;

             after(grammarAccess.getTcpRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleTcp2205); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleTcp"


    // $ANTLR start "ruleTcp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1089:1: ruleTcp : ( 'tcp' ) ;
    public final void ruleTcp() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1093:2: ( ( 'tcp' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1094:1: ( 'tcp' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1094:1: ( 'tcp' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1095:1: 'tcp'
            {
             before(grammarAccess.getTcpAccess().getTcpKeyword()); 
            match(input,30,FOLLOW_30_in_ruleTcp2232); 
             after(grammarAccess.getTcpAccess().getTcpKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleTcp"


    // $ANTLR start "entryRuleUdp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1110:1: entryRuleUdp : ruleUdp EOF ;
    public final void entryRuleUdp() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1111:1: ( ruleUdp EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1112:1: ruleUdp EOF
            {
             before(grammarAccess.getUdpRule()); 
            pushFollow(FOLLOW_ruleUdp_in_entryRuleUdp2260);
            ruleUdp();

            state._fsp--;

             after(grammarAccess.getUdpRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleUdp2267); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleUdp"


    // $ANTLR start "ruleUdp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1119:1: ruleUdp : ( 'udp' ) ;
    public final void ruleUdp() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1123:2: ( ( 'udp' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1124:1: ( 'udp' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1124:1: ( 'udp' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1125:1: 'udp'
            {
             before(grammarAccess.getUdpAccess().getUdpKeyword()); 
            match(input,31,FOLLOW_31_in_ruleUdp2294); 
             after(grammarAccess.getUdpAccess().getUdpKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleUdp"


    // $ANTLR start "entryRuleIcmp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1140:1: entryRuleIcmp : ruleIcmp EOF ;
    public final void entryRuleIcmp() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1141:1: ( ruleIcmp EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1142:1: ruleIcmp EOF
            {
             before(grammarAccess.getIcmpRule()); 
            pushFollow(FOLLOW_ruleIcmp_in_entryRuleIcmp2322);
            ruleIcmp();

            state._fsp--;

             after(grammarAccess.getIcmpRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleIcmp2329); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleIcmp"


    // $ANTLR start "ruleIcmp"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1149:1: ruleIcmp : ( 'icmp' ) ;
    public final void ruleIcmp() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1153:2: ( ( 'icmp' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1154:1: ( 'icmp' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1154:1: ( 'icmp' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1155:1: 'icmp'
            {
             before(grammarAccess.getIcmpAccess().getIcmpKeyword()); 
            match(input,32,FOLLOW_32_in_ruleIcmp2356); 
             after(grammarAccess.getIcmpAccess().getIcmpKeyword()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleIcmp"


    // $ANTLR start "entryRuleTarget"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1170:1: entryRuleTarget : ruleTarget EOF ;
    public final void entryRuleTarget() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1171:1: ( ruleTarget EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1172:1: ruleTarget EOF
            {
             before(grammarAccess.getTargetRule()); 
            pushFollow(FOLLOW_ruleTarget_in_entryRuleTarget2384);
            ruleTarget();

            state._fsp--;

             after(grammarAccess.getTargetRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleTarget2391); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleTarget"


    // $ANTLR start "ruleTarget"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1179:1: ruleTarget : ( RULE_ID ) ;
    public final void ruleTarget() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1183:2: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1184:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1184:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1185:1: RULE_ID
            {
             before(grammarAccess.getTargetAccess().getIDTerminalRuleCall()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_ruleTarget2417); 
             after(grammarAccess.getTargetAccess().getIDTerminalRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleTarget"


    // $ANTLR start "entryRuleChain"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1198:1: entryRuleChain : ruleChain EOF ;
    public final void entryRuleChain() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1199:1: ( ruleChain EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1200:1: ruleChain EOF
            {
             before(grammarAccess.getChainRule()); 
            pushFollow(FOLLOW_ruleChain_in_entryRuleChain2443);
            ruleChain();

            state._fsp--;

             after(grammarAccess.getChainRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleChain2450); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleChain"


    // $ANTLR start "ruleChain"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1207:1: ruleChain : ( ( rule__Chain__ChainNameAssignment ) ) ;
    public final void ruleChain() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1211:2: ( ( ( rule__Chain__ChainNameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1212:1: ( ( rule__Chain__ChainNameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1212:1: ( ( rule__Chain__ChainNameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1213:1: ( rule__Chain__ChainNameAssignment )
            {
             before(grammarAccess.getChainAccess().getChainNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1214:1: ( rule__Chain__ChainNameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1214:2: rule__Chain__ChainNameAssignment
            {
            pushFollow(FOLLOW_rule__Chain__ChainNameAssignment_in_ruleChain2476);
            rule__Chain__ChainNameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getChainAccess().getChainNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleChain"


    // $ANTLR start "entryRuleChainDeclaration"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1228:1: entryRuleChainDeclaration : ruleChainDeclaration EOF ;
    public final void entryRuleChainDeclaration() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1229:1: ( ruleChainDeclaration EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1230:1: ruleChainDeclaration EOF
            {
             before(grammarAccess.getChainDeclarationRule()); 
            pushFollow(FOLLOW_ruleChainDeclaration_in_entryRuleChainDeclaration2505);
            ruleChainDeclaration();

            state._fsp--;

             after(grammarAccess.getChainDeclarationRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleChainDeclaration2512); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleChainDeclaration"


    // $ANTLR start "ruleChainDeclaration"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1237:1: ruleChainDeclaration : ( ( rule__ChainDeclaration__Group__0 ) ) ;
    public final void ruleChainDeclaration() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1241:2: ( ( ( rule__ChainDeclaration__Group__0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1242:1: ( ( rule__ChainDeclaration__Group__0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1242:1: ( ( rule__ChainDeclaration__Group__0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1243:1: ( rule__ChainDeclaration__Group__0 )
            {
             before(grammarAccess.getChainDeclarationAccess().getGroup()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1244:1: ( rule__ChainDeclaration__Group__0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1244:2: rule__ChainDeclaration__Group__0
            {
            pushFollow(FOLLOW_rule__ChainDeclaration__Group__0_in_ruleChainDeclaration2538);
            rule__ChainDeclaration__Group__0();

            state._fsp--;


            }

             after(grammarAccess.getChainDeclarationAccess().getGroup()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleChainDeclaration"


    // $ANTLR start "entryRuleChainName"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1256:1: entryRuleChainName : ruleChainName EOF ;
    public final void entryRuleChainName() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1257:1: ( ruleChainName EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1258:1: ruleChainName EOF
            {
             before(grammarAccess.getChainNameRule()); 
            pushFollow(FOLLOW_ruleChainName_in_entryRuleChainName2565);
            ruleChainName();

            state._fsp--;

             after(grammarAccess.getChainNameRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleChainName2572); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleChainName"


    // $ANTLR start "ruleChainName"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1265:1: ruleChainName : ( ( rule__ChainName__NameAssignment ) ) ;
    public final void ruleChainName() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1269:2: ( ( ( rule__ChainName__NameAssignment ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1270:1: ( ( rule__ChainName__NameAssignment ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1270:1: ( ( rule__ChainName__NameAssignment ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1271:1: ( rule__ChainName__NameAssignment )
            {
             before(grammarAccess.getChainNameAccess().getNameAssignment()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1272:1: ( rule__ChainName__NameAssignment )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1272:2: rule__ChainName__NameAssignment
            {
            pushFollow(FOLLOW_rule__ChainName__NameAssignment_in_ruleChainName2598);
            rule__ChainName__NameAssignment();

            state._fsp--;


            }

             after(grammarAccess.getChainNameAccess().getNameAssignment()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleChainName"


    // $ANTLR start "entryRuleIPExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1284:1: entryRuleIPExpr : ruleIPExpr EOF ;
    public final void entryRuleIPExpr() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1285:1: ( ruleIPExpr EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1286:1: ruleIPExpr EOF
            {
             before(grammarAccess.getIPExprRule()); 
            pushFollow(FOLLOW_ruleIPExpr_in_entryRuleIPExpr2625);
            ruleIPExpr();

            state._fsp--;

             after(grammarAccess.getIPExprRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleIPExpr2632); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleIPExpr"


    // $ANTLR start "ruleIPExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1293:1: ruleIPExpr : ( ( rule__IPExpr__Group__0 ) ) ;
    public final void ruleIPExpr() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1297:2: ( ( ( rule__IPExpr__Group__0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1298:1: ( ( rule__IPExpr__Group__0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1298:1: ( ( rule__IPExpr__Group__0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1299:1: ( rule__IPExpr__Group__0 )
            {
             before(grammarAccess.getIPExprAccess().getGroup()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1300:1: ( rule__IPExpr__Group__0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1300:2: rule__IPExpr__Group__0
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__0_in_ruleIPExpr2658);
            rule__IPExpr__Group__0();

            state._fsp--;


            }

             after(grammarAccess.getIPExprAccess().getGroup()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleIPExpr"


    // $ANTLR start "entryRuleipByteExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1312:1: entryRuleipByteExpr : ruleipByteExpr EOF ;
    public final void entryRuleipByteExpr() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1313:1: ( ruleipByteExpr EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1314:1: ruleipByteExpr EOF
            {
             before(grammarAccess.getIpByteExprRule()); 
            pushFollow(FOLLOW_ruleipByteExpr_in_entryRuleipByteExpr2685);
            ruleipByteExpr();

            state._fsp--;

             after(grammarAccess.getIpByteExprRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleipByteExpr2692); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleipByteExpr"


    // $ANTLR start "ruleipByteExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1321:1: ruleipByteExpr : ( RULE_INT ) ;
    public final void ruleipByteExpr() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1325:2: ( ( RULE_INT ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1326:1: ( RULE_INT )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1326:1: ( RULE_INT )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1327:1: RULE_INT
            {
             before(grammarAccess.getIpByteExprAccess().getINTTerminalRuleCall()); 
            match(input,RULE_INT,FOLLOW_RULE_INT_in_ruleipByteExpr2718); 
             after(grammarAccess.getIpByteExprAccess().getINTTerminalRuleCall()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleipByteExpr"


    // $ANTLR start "entryRuleIpRangeExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1340:1: entryRuleIpRangeExpr : ruleIpRangeExpr EOF ;
    public final void entryRuleIpRangeExpr() throws RecognitionException {
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1341:1: ( ruleIpRangeExpr EOF )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1342:1: ruleIpRangeExpr EOF
            {
             before(grammarAccess.getIpRangeExprRule()); 
            pushFollow(FOLLOW_ruleIpRangeExpr_in_entryRuleIpRangeExpr2744);
            ruleIpRangeExpr();

            state._fsp--;

             after(grammarAccess.getIpRangeExprRule()); 
            match(input,EOF,FOLLOW_EOF_in_entryRuleIpRangeExpr2751); 

            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {
        }
        return ;
    }
    // $ANTLR end "entryRuleIpRangeExpr"


    // $ANTLR start "ruleIpRangeExpr"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1349:1: ruleIpRangeExpr : ( ( rule__IpRangeExpr__Group__0 ) ) ;
    public final void ruleIpRangeExpr() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1353:2: ( ( ( rule__IpRangeExpr__Group__0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1354:1: ( ( rule__IpRangeExpr__Group__0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1354:1: ( ( rule__IpRangeExpr__Group__0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1355:1: ( rule__IpRangeExpr__Group__0 )
            {
             before(grammarAccess.getIpRangeExprAccess().getGroup()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1356:1: ( rule__IpRangeExpr__Group__0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1356:2: rule__IpRangeExpr__Group__0
            {
            pushFollow(FOLLOW_rule__IpRangeExpr__Group__0_in_ruleIpRangeExpr2777);
            rule__IpRangeExpr__Group__0();

            state._fsp--;


            }

             after(grammarAccess.getIpRangeExprAccess().getGroup()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "ruleIpRangeExpr"


    // $ANTLR start "rule__Rule__Alternatives"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1368:1: rule__Rule__Alternatives : ( ( ( rule__Rule__DeclarationAssignment_0 ) ) | ( ( rule__Rule__FilterAssignment_1 ) ) );
    public final void rule__Rule__Alternatives() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1372:1: ( ( ( rule__Rule__DeclarationAssignment_0 ) ) | ( ( rule__Rule__FilterAssignment_1 ) ) )
            int alt2=2;
            int LA2_0 = input.LA(1);

            if ( (LA2_0==36) ) {
                int LA2_1 = input.LA(2);

                if ( (LA2_1==52) ) {
                    alt2=1;
                }
                else if ( ((LA2_1>=33 && LA2_1<=35)) ) {
                    alt2=2;
                }
                else {
                    NoViableAltException nvae =
                        new NoViableAltException("", 2, 1, input);

                    throw nvae;
                }
            }
            else {
                NoViableAltException nvae =
                    new NoViableAltException("", 2, 0, input);

                throw nvae;
            }
            switch (alt2) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1373:1: ( ( rule__Rule__DeclarationAssignment_0 ) )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1373:1: ( ( rule__Rule__DeclarationAssignment_0 ) )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1374:1: ( rule__Rule__DeclarationAssignment_0 )
                    {
                     before(grammarAccess.getRuleAccess().getDeclarationAssignment_0()); 
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1375:1: ( rule__Rule__DeclarationAssignment_0 )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1375:2: rule__Rule__DeclarationAssignment_0
                    {
                    pushFollow(FOLLOW_rule__Rule__DeclarationAssignment_0_in_rule__Rule__Alternatives2813);
                    rule__Rule__DeclarationAssignment_0();

                    state._fsp--;


                    }

                     after(grammarAccess.getRuleAccess().getDeclarationAssignment_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1379:6: ( ( rule__Rule__FilterAssignment_1 ) )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1379:6: ( ( rule__Rule__FilterAssignment_1 ) )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1380:1: ( rule__Rule__FilterAssignment_1 )
                    {
                     before(grammarAccess.getRuleAccess().getFilterAssignment_1()); 
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1381:1: ( rule__Rule__FilterAssignment_1 )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1381:2: rule__Rule__FilterAssignment_1
                    {
                    pushFollow(FOLLOW_rule__Rule__FilterAssignment_1_in_rule__Rule__Alternatives2831);
                    rule__Rule__FilterAssignment_1();

                    state._fsp--;


                    }

                     after(grammarAccess.getRuleAccess().getFilterAssignment_1()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Rule__Alternatives"


    // $ANTLR start "rule__FilterSpec__OptionAlternatives_1_0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1390:1: rule__FilterSpec__OptionAlternatives_1_0 : ( ( '-A' ) | ( '-D' ) | ( '-P' ) );
    public final void rule__FilterSpec__OptionAlternatives_1_0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1394:1: ( ( '-A' ) | ( '-D' ) | ( '-P' ) )
            int alt3=3;
            switch ( input.LA(1) ) {
            case 33:
                {
                alt3=1;
                }
                break;
            case 34:
                {
                alt3=2;
                }
                break;
            case 35:
                {
                alt3=3;
                }
                break;
            default:
                NoViableAltException nvae =
                    new NoViableAltException("", 3, 0, input);

                throw nvae;
            }

            switch (alt3) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1395:1: ( '-A' )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1395:1: ( '-A' )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1396:1: '-A'
                    {
                     before(grammarAccess.getFilterSpecAccess().getOptionAKeyword_1_0_0()); 
                    match(input,33,FOLLOW_33_in_rule__FilterSpec__OptionAlternatives_1_02865); 
                     after(grammarAccess.getFilterSpecAccess().getOptionAKeyword_1_0_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1403:6: ( '-D' )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1403:6: ( '-D' )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1404:1: '-D'
                    {
                     before(grammarAccess.getFilterSpecAccess().getOptionDKeyword_1_0_1()); 
                    match(input,34,FOLLOW_34_in_rule__FilterSpec__OptionAlternatives_1_02885); 
                     after(grammarAccess.getFilterSpecAccess().getOptionDKeyword_1_0_1()); 

                    }


                    }
                    break;
                case 3 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1411:6: ( '-P' )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1411:6: ( '-P' )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1412:1: '-P'
                    {
                     before(grammarAccess.getFilterSpecAccess().getOptionPKeyword_1_0_2()); 
                    match(input,35,FOLLOW_35_in_rule__FilterSpec__OptionAlternatives_1_02905); 
                     after(grammarAccess.getFilterSpecAccess().getOptionPKeyword_1_0_2()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__OptionAlternatives_1_0"


    // $ANTLR start "rule__Match__NameAlternatives_0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1424:1: rule__Match__NameAlternatives_0 : ( ( ruleConntrack ) | ( ruleStateMatch ) );
    public final void rule__Match__NameAlternatives_0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1428:1: ( ( ruleConntrack ) | ( ruleStateMatch ) )
            int alt4=2;
            int LA4_0 = input.LA(1);

            if ( (LA4_0==11) ) {
                alt4=1;
            }
            else if ( (LA4_0==12) ) {
                alt4=2;
            }
            else {
                NoViableAltException nvae =
                    new NoViableAltException("", 4, 0, input);

                throw nvae;
            }
            switch (alt4) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1429:1: ( ruleConntrack )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1429:1: ( ruleConntrack )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1430:1: ruleConntrack
                    {
                     before(grammarAccess.getMatchAccess().getNameConntrackParserRuleCall_0_0()); 
                    pushFollow(FOLLOW_ruleConntrack_in_rule__Match__NameAlternatives_02939);
                    ruleConntrack();

                    state._fsp--;

                     after(grammarAccess.getMatchAccess().getNameConntrackParserRuleCall_0_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1435:6: ( ruleStateMatch )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1435:6: ( ruleStateMatch )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1436:1: ruleStateMatch
                    {
                     before(grammarAccess.getMatchAccess().getNameStateMatchParserRuleCall_0_1()); 
                    pushFollow(FOLLOW_ruleStateMatch_in_rule__Match__NameAlternatives_02956);
                    ruleStateMatch();

                    state._fsp--;

                     after(grammarAccess.getMatchAccess().getNameStateMatchParserRuleCall_0_1()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Match__NameAlternatives_0"


    // $ANTLR start "rule__State__NameAlternatives_0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1446:1: rule__State__NameAlternatives_0 : ( ( ruleNormalMatchStates ) | ( ruleStateFulMatchStates ) );
    public final void rule__State__NameAlternatives_0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1450:1: ( ( ruleNormalMatchStates ) | ( ruleStateFulMatchStates ) )
            int alt5=2;
            int LA5_0 = input.LA(1);

            if ( (LA5_0==13) ) {
                alt5=1;
            }
            else if ( ((LA5_0>=14 && LA5_0<=22)) ) {
                alt5=2;
            }
            else {
                NoViableAltException nvae =
                    new NoViableAltException("", 5, 0, input);

                throw nvae;
            }
            switch (alt5) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1451:1: ( ruleNormalMatchStates )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1451:1: ( ruleNormalMatchStates )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1452:1: ruleNormalMatchStates
                    {
                     before(grammarAccess.getStateAccess().getNameNormalMatchStatesParserRuleCall_0_0()); 
                    pushFollow(FOLLOW_ruleNormalMatchStates_in_rule__State__NameAlternatives_02988);
                    ruleNormalMatchStates();

                    state._fsp--;

                     after(grammarAccess.getStateAccess().getNameNormalMatchStatesParserRuleCall_0_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1457:6: ( ruleStateFulMatchStates )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1457:6: ( ruleStateFulMatchStates )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1458:1: ruleStateFulMatchStates
                    {
                     before(grammarAccess.getStateAccess().getNameStateFulMatchStatesParserRuleCall_0_1()); 
                    pushFollow(FOLLOW_ruleStateFulMatchStates_in_rule__State__NameAlternatives_03005);
                    ruleStateFulMatchStates();

                    state._fsp--;

                     after(grammarAccess.getStateAccess().getNameStateFulMatchStatesParserRuleCall_0_1()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__State__NameAlternatives_0"


    // $ANTLR start "rule__StateFulMatchStates__Alternatives"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1468:1: rule__StateFulMatchStates__Alternatives : ( ( ruleNoneS ) | ( ruleSynSent ) | ( ruleSynRecv ) | ( ruleEstablished ) | ( ruleFinWait ) | ( ruleCloseWait ) | ( ruleLastAck ) | ( ruleTimeWait ) | ( ruleClose ) );
    public final void rule__StateFulMatchStates__Alternatives() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1472:1: ( ( ruleNoneS ) | ( ruleSynSent ) | ( ruleSynRecv ) | ( ruleEstablished ) | ( ruleFinWait ) | ( ruleCloseWait ) | ( ruleLastAck ) | ( ruleTimeWait ) | ( ruleClose ) )
            int alt6=9;
            switch ( input.LA(1) ) {
            case 14:
                {
                alt6=1;
                }
                break;
            case 15:
                {
                alt6=2;
                }
                break;
            case 16:
                {
                alt6=3;
                }
                break;
            case 17:
                {
                alt6=4;
                }
                break;
            case 18:
                {
                alt6=5;
                }
                break;
            case 19:
                {
                alt6=6;
                }
                break;
            case 20:
                {
                alt6=7;
                }
                break;
            case 21:
                {
                alt6=8;
                }
                break;
            case 22:
                {
                alt6=9;
                }
                break;
            default:
                NoViableAltException nvae =
                    new NoViableAltException("", 6, 0, input);

                throw nvae;
            }

            switch (alt6) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1473:1: ( ruleNoneS )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1473:1: ( ruleNoneS )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1474:1: ruleNoneS
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getNoneSParserRuleCall_0()); 
                    pushFollow(FOLLOW_ruleNoneS_in_rule__StateFulMatchStates__Alternatives3037);
                    ruleNoneS();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getNoneSParserRuleCall_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1479:6: ( ruleSynSent )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1479:6: ( ruleSynSent )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1480:1: ruleSynSent
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getSynSentParserRuleCall_1()); 
                    pushFollow(FOLLOW_ruleSynSent_in_rule__StateFulMatchStates__Alternatives3054);
                    ruleSynSent();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getSynSentParserRuleCall_1()); 

                    }


                    }
                    break;
                case 3 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1485:6: ( ruleSynRecv )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1485:6: ( ruleSynRecv )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1486:1: ruleSynRecv
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getSynRecvParserRuleCall_2()); 
                    pushFollow(FOLLOW_ruleSynRecv_in_rule__StateFulMatchStates__Alternatives3071);
                    ruleSynRecv();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getSynRecvParserRuleCall_2()); 

                    }


                    }
                    break;
                case 4 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1491:6: ( ruleEstablished )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1491:6: ( ruleEstablished )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1492:1: ruleEstablished
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getEstablishedParserRuleCall_3()); 
                    pushFollow(FOLLOW_ruleEstablished_in_rule__StateFulMatchStates__Alternatives3088);
                    ruleEstablished();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getEstablishedParserRuleCall_3()); 

                    }


                    }
                    break;
                case 5 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1497:6: ( ruleFinWait )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1497:6: ( ruleFinWait )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1498:1: ruleFinWait
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getFinWaitParserRuleCall_4()); 
                    pushFollow(FOLLOW_ruleFinWait_in_rule__StateFulMatchStates__Alternatives3105);
                    ruleFinWait();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getFinWaitParserRuleCall_4()); 

                    }


                    }
                    break;
                case 6 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1503:6: ( ruleCloseWait )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1503:6: ( ruleCloseWait )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1504:1: ruleCloseWait
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getCloseWaitParserRuleCall_5()); 
                    pushFollow(FOLLOW_ruleCloseWait_in_rule__StateFulMatchStates__Alternatives3122);
                    ruleCloseWait();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getCloseWaitParserRuleCall_5()); 

                    }


                    }
                    break;
                case 7 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1509:6: ( ruleLastAck )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1509:6: ( ruleLastAck )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1510:1: ruleLastAck
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getLastAckParserRuleCall_6()); 
                    pushFollow(FOLLOW_ruleLastAck_in_rule__StateFulMatchStates__Alternatives3139);
                    ruleLastAck();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getLastAckParserRuleCall_6()); 

                    }


                    }
                    break;
                case 8 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1515:6: ( ruleTimeWait )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1515:6: ( ruleTimeWait )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1516:1: ruleTimeWait
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getTimeWaitParserRuleCall_7()); 
                    pushFollow(FOLLOW_ruleTimeWait_in_rule__StateFulMatchStates__Alternatives3156);
                    ruleTimeWait();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getTimeWaitParserRuleCall_7()); 

                    }


                    }
                    break;
                case 9 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1521:6: ( ruleClose )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1521:6: ( ruleClose )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1522:1: ruleClose
                    {
                     before(grammarAccess.getStateFulMatchStatesAccess().getCloseParserRuleCall_8()); 
                    pushFollow(FOLLOW_ruleClose_in_rule__StateFulMatchStates__Alternatives3173);
                    ruleClose();

                    state._fsp--;

                     after(grammarAccess.getStateFulMatchStatesAccess().getCloseParserRuleCall_8()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__StateFulMatchStates__Alternatives"


    // $ANTLR start "rule__TCPFlag__NameAlternatives_0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1532:1: rule__TCPFlag__NameAlternatives_0 : ( ( ruleSyn ) | ( ruleAck ) | ( ruleFin ) | ( ruleRst ) | ( ruleAll ) | ( ruleNone ) | ( rulePsh ) | ( ruleUrg ) );
    public final void rule__TCPFlag__NameAlternatives_0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1536:1: ( ( ruleSyn ) | ( ruleAck ) | ( ruleFin ) | ( ruleRst ) | ( ruleAll ) | ( ruleNone ) | ( rulePsh ) | ( ruleUrg ) )
            int alt7=8;
            switch ( input.LA(1) ) {
            case 23:
                {
                alt7=1;
                }
                break;
            case 24:
                {
                alt7=2;
                }
                break;
            case 25:
                {
                alt7=3;
                }
                break;
            case 26:
                {
                alt7=4;
                }
                break;
            case 27:
                {
                alt7=5;
                }
                break;
            case 14:
                {
                alt7=6;
                }
                break;
            case 28:
                {
                alt7=7;
                }
                break;
            case 29:
                {
                alt7=8;
                }
                break;
            default:
                NoViableAltException nvae =
                    new NoViableAltException("", 7, 0, input);

                throw nvae;
            }

            switch (alt7) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1537:1: ( ruleSyn )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1537:1: ( ruleSyn )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1538:1: ruleSyn
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameSynParserRuleCall_0_0()); 
                    pushFollow(FOLLOW_ruleSyn_in_rule__TCPFlag__NameAlternatives_03205);
                    ruleSyn();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameSynParserRuleCall_0_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1543:6: ( ruleAck )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1543:6: ( ruleAck )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1544:1: ruleAck
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameAckParserRuleCall_0_1()); 
                    pushFollow(FOLLOW_ruleAck_in_rule__TCPFlag__NameAlternatives_03222);
                    ruleAck();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameAckParserRuleCall_0_1()); 

                    }


                    }
                    break;
                case 3 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1549:6: ( ruleFin )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1549:6: ( ruleFin )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1550:1: ruleFin
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameFinParserRuleCall_0_2()); 
                    pushFollow(FOLLOW_ruleFin_in_rule__TCPFlag__NameAlternatives_03239);
                    ruleFin();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameFinParserRuleCall_0_2()); 

                    }


                    }
                    break;
                case 4 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1555:6: ( ruleRst )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1555:6: ( ruleRst )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1556:1: ruleRst
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameRstParserRuleCall_0_3()); 
                    pushFollow(FOLLOW_ruleRst_in_rule__TCPFlag__NameAlternatives_03256);
                    ruleRst();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameRstParserRuleCall_0_3()); 

                    }


                    }
                    break;
                case 5 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1561:6: ( ruleAll )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1561:6: ( ruleAll )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1562:1: ruleAll
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameAllParserRuleCall_0_4()); 
                    pushFollow(FOLLOW_ruleAll_in_rule__TCPFlag__NameAlternatives_03273);
                    ruleAll();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameAllParserRuleCall_0_4()); 

                    }


                    }
                    break;
                case 6 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1567:6: ( ruleNone )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1567:6: ( ruleNone )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1568:1: ruleNone
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameNoneParserRuleCall_0_5()); 
                    pushFollow(FOLLOW_ruleNone_in_rule__TCPFlag__NameAlternatives_03290);
                    ruleNone();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameNoneParserRuleCall_0_5()); 

                    }


                    }
                    break;
                case 7 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1573:6: ( rulePsh )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1573:6: ( rulePsh )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1574:1: rulePsh
                    {
                     before(grammarAccess.getTCPFlagAccess().getNamePshParserRuleCall_0_6()); 
                    pushFollow(FOLLOW_rulePsh_in_rule__TCPFlag__NameAlternatives_03307);
                    rulePsh();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNamePshParserRuleCall_0_6()); 

                    }


                    }
                    break;
                case 8 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1579:6: ( ruleUrg )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1579:6: ( ruleUrg )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1580:1: ruleUrg
                    {
                     before(grammarAccess.getTCPFlagAccess().getNameUrgParserRuleCall_0_7()); 
                    pushFollow(FOLLOW_ruleUrg_in_rule__TCPFlag__NameAlternatives_03324);
                    ruleUrg();

                    state._fsp--;

                     after(grammarAccess.getTCPFlagAccess().getNameUrgParserRuleCall_0_7()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__TCPFlag__NameAlternatives_0"


    // $ANTLR start "rule__Protocol__Alternatives"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1590:1: rule__Protocol__Alternatives : ( ( ruleTcp ) | ( ruleUdp ) | ( ruleIcmp ) );
    public final void rule__Protocol__Alternatives() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1594:1: ( ( ruleTcp ) | ( ruleUdp ) | ( ruleIcmp ) )
            int alt8=3;
            switch ( input.LA(1) ) {
            case 30:
                {
                alt8=1;
                }
                break;
            case 31:
                {
                alt8=2;
                }
                break;
            case 32:
                {
                alt8=3;
                }
                break;
            default:
                NoViableAltException nvae =
                    new NoViableAltException("", 8, 0, input);

                throw nvae;
            }

            switch (alt8) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1595:1: ( ruleTcp )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1595:1: ( ruleTcp )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1596:1: ruleTcp
                    {
                     before(grammarAccess.getProtocolAccess().getTcpParserRuleCall_0()); 
                    pushFollow(FOLLOW_ruleTcp_in_rule__Protocol__Alternatives3356);
                    ruleTcp();

                    state._fsp--;

                     after(grammarAccess.getProtocolAccess().getTcpParserRuleCall_0()); 

                    }


                    }
                    break;
                case 2 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1601:6: ( ruleUdp )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1601:6: ( ruleUdp )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1602:1: ruleUdp
                    {
                     before(grammarAccess.getProtocolAccess().getUdpParserRuleCall_1()); 
                    pushFollow(FOLLOW_ruleUdp_in_rule__Protocol__Alternatives3373);
                    ruleUdp();

                    state._fsp--;

                     after(grammarAccess.getProtocolAccess().getUdpParserRuleCall_1()); 

                    }


                    }
                    break;
                case 3 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1607:6: ( ruleIcmp )
                    {
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1607:6: ( ruleIcmp )
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1608:1: ruleIcmp
                    {
                     before(grammarAccess.getProtocolAccess().getIcmpParserRuleCall_2()); 
                    pushFollow(FOLLOW_ruleIcmp_in_rule__Protocol__Alternatives3390);
                    ruleIcmp();

                    state._fsp--;

                     after(grammarAccess.getProtocolAccess().getIcmpParserRuleCall_2()); 

                    }


                    }
                    break;

            }
        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Protocol__Alternatives"


    // $ANTLR start "rule__FilterSpec__Group__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1620:1: rule__FilterSpec__Group__0 : rule__FilterSpec__Group__0__Impl rule__FilterSpec__Group__1 ;
    public final void rule__FilterSpec__Group__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1624:1: ( rule__FilterSpec__Group__0__Impl rule__FilterSpec__Group__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1625:2: rule__FilterSpec__Group__0__Impl rule__FilterSpec__Group__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__0__Impl_in_rule__FilterSpec__Group__03420);
            rule__FilterSpec__Group__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__1_in_rule__FilterSpec__Group__03423);
            rule__FilterSpec__Group__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__0"


    // $ANTLR start "rule__FilterSpec__Group__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1632:1: rule__FilterSpec__Group__0__Impl : ( 'iptables' ) ;
    public final void rule__FilterSpec__Group__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1636:1: ( ( 'iptables' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1637:1: ( 'iptables' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1637:1: ( 'iptables' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1638:1: 'iptables'
            {
             before(grammarAccess.getFilterSpecAccess().getIptablesKeyword_0()); 
            match(input,36,FOLLOW_36_in_rule__FilterSpec__Group__0__Impl3451); 
             after(grammarAccess.getFilterSpecAccess().getIptablesKeyword_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1651:1: rule__FilterSpec__Group__1 : rule__FilterSpec__Group__1__Impl rule__FilterSpec__Group__2 ;
    public final void rule__FilterSpec__Group__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1655:1: ( rule__FilterSpec__Group__1__Impl rule__FilterSpec__Group__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1656:2: rule__FilterSpec__Group__1__Impl rule__FilterSpec__Group__2
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__1__Impl_in_rule__FilterSpec__Group__13482);
            rule__FilterSpec__Group__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__2_in_rule__FilterSpec__Group__13485);
            rule__FilterSpec__Group__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__1"


    // $ANTLR start "rule__FilterSpec__Group__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1663:1: rule__FilterSpec__Group__1__Impl : ( ( rule__FilterSpec__OptionAssignment_1 ) ) ;
    public final void rule__FilterSpec__Group__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1667:1: ( ( ( rule__FilterSpec__OptionAssignment_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1668:1: ( ( rule__FilterSpec__OptionAssignment_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1668:1: ( ( rule__FilterSpec__OptionAssignment_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1669:1: ( rule__FilterSpec__OptionAssignment_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getOptionAssignment_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1670:1: ( rule__FilterSpec__OptionAssignment_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1670:2: rule__FilterSpec__OptionAssignment_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__OptionAssignment_1_in_rule__FilterSpec__Group__1__Impl3512);
            rule__FilterSpec__OptionAssignment_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getOptionAssignment_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1680:1: rule__FilterSpec__Group__2 : rule__FilterSpec__Group__2__Impl rule__FilterSpec__Group__3 ;
    public final void rule__FilterSpec__Group__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1684:1: ( rule__FilterSpec__Group__2__Impl rule__FilterSpec__Group__3 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1685:2: rule__FilterSpec__Group__2__Impl rule__FilterSpec__Group__3
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__2__Impl_in_rule__FilterSpec__Group__23542);
            rule__FilterSpec__Group__2__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__3_in_rule__FilterSpec__Group__23545);
            rule__FilterSpec__Group__3();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__2"


    // $ANTLR start "rule__FilterSpec__Group__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1692:1: rule__FilterSpec__Group__2__Impl : ( ( rule__FilterSpec__ChainAssignment_2 ) ) ;
    public final void rule__FilterSpec__Group__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1696:1: ( ( ( rule__FilterSpec__ChainAssignment_2 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1697:1: ( ( rule__FilterSpec__ChainAssignment_2 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1697:1: ( ( rule__FilterSpec__ChainAssignment_2 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1698:1: ( rule__FilterSpec__ChainAssignment_2 )
            {
             before(grammarAccess.getFilterSpecAccess().getChainAssignment_2()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1699:1: ( rule__FilterSpec__ChainAssignment_2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1699:2: rule__FilterSpec__ChainAssignment_2
            {
            pushFollow(FOLLOW_rule__FilterSpec__ChainAssignment_2_in_rule__FilterSpec__Group__2__Impl3572);
            rule__FilterSpec__ChainAssignment_2();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getChainAssignment_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__2__Impl"


    // $ANTLR start "rule__FilterSpec__Group__3"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1709:1: rule__FilterSpec__Group__3 : rule__FilterSpec__Group__3__Impl rule__FilterSpec__Group__4 ;
    public final void rule__FilterSpec__Group__3() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1713:1: ( rule__FilterSpec__Group__3__Impl rule__FilterSpec__Group__4 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1714:2: rule__FilterSpec__Group__3__Impl rule__FilterSpec__Group__4
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__3__Impl_in_rule__FilterSpec__Group__33602);
            rule__FilterSpec__Group__3__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__4_in_rule__FilterSpec__Group__33605);
            rule__FilterSpec__Group__4();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__3"


    // $ANTLR start "rule__FilterSpec__Group__3__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1721:1: rule__FilterSpec__Group__3__Impl : ( ( rule__FilterSpec__Group_3__0 )? ) ;
    public final void rule__FilterSpec__Group__3__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1725:1: ( ( ( rule__FilterSpec__Group_3__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1726:1: ( ( rule__FilterSpec__Group_3__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1726:1: ( ( rule__FilterSpec__Group_3__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1727:1: ( rule__FilterSpec__Group_3__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_3()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1728:1: ( rule__FilterSpec__Group_3__0 )?
            int alt9=2;
            int LA9_0 = input.LA(1);

            if ( (LA9_0==38) ) {
                alt9=1;
            }
            switch (alt9) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1728:2: rule__FilterSpec__Group_3__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_3__0_in_rule__FilterSpec__Group__3__Impl3632);
                    rule__FilterSpec__Group_3__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_3()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__3__Impl"


    // $ANTLR start "rule__FilterSpec__Group__4"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1738:1: rule__FilterSpec__Group__4 : rule__FilterSpec__Group__4__Impl rule__FilterSpec__Group__5 ;
    public final void rule__FilterSpec__Group__4() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1742:1: ( rule__FilterSpec__Group__4__Impl rule__FilterSpec__Group__5 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1743:2: rule__FilterSpec__Group__4__Impl rule__FilterSpec__Group__5
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__4__Impl_in_rule__FilterSpec__Group__43663);
            rule__FilterSpec__Group__4__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__5_in_rule__FilterSpec__Group__43666);
            rule__FilterSpec__Group__5();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__4"


    // $ANTLR start "rule__FilterSpec__Group__4__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1750:1: rule__FilterSpec__Group__4__Impl : ( ( rule__FilterSpec__Group_4__0 )? ) ;
    public final void rule__FilterSpec__Group__4__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1754:1: ( ( ( rule__FilterSpec__Group_4__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1755:1: ( ( rule__FilterSpec__Group_4__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1755:1: ( ( rule__FilterSpec__Group_4__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1756:1: ( rule__FilterSpec__Group_4__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_4()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1757:1: ( rule__FilterSpec__Group_4__0 )?
            int alt10=2;
            int LA10_0 = input.LA(1);

            if ( (LA10_0==39) ) {
                alt10=1;
            }
            switch (alt10) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1757:2: rule__FilterSpec__Group_4__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_4__0_in_rule__FilterSpec__Group__4__Impl3693);
                    rule__FilterSpec__Group_4__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_4()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__4__Impl"


    // $ANTLR start "rule__FilterSpec__Group__5"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1767:1: rule__FilterSpec__Group__5 : rule__FilterSpec__Group__5__Impl rule__FilterSpec__Group__6 ;
    public final void rule__FilterSpec__Group__5() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1771:1: ( rule__FilterSpec__Group__5__Impl rule__FilterSpec__Group__6 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1772:2: rule__FilterSpec__Group__5__Impl rule__FilterSpec__Group__6
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__5__Impl_in_rule__FilterSpec__Group__53724);
            rule__FilterSpec__Group__5__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__6_in_rule__FilterSpec__Group__53727);
            rule__FilterSpec__Group__6();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__5"


    // $ANTLR start "rule__FilterSpec__Group__5__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1779:1: rule__FilterSpec__Group__5__Impl : ( ( rule__FilterSpec__Group_5__0 )? ) ;
    public final void rule__FilterSpec__Group__5__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1783:1: ( ( ( rule__FilterSpec__Group_5__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1784:1: ( ( rule__FilterSpec__Group_5__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1784:1: ( ( rule__FilterSpec__Group_5__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1785:1: ( rule__FilterSpec__Group_5__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_5()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1786:1: ( rule__FilterSpec__Group_5__0 )?
            int alt11=2;
            int LA11_0 = input.LA(1);

            if ( (LA11_0==40) ) {
                alt11=1;
            }
            switch (alt11) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1786:2: rule__FilterSpec__Group_5__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_5__0_in_rule__FilterSpec__Group__5__Impl3754);
                    rule__FilterSpec__Group_5__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_5()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__5__Impl"


    // $ANTLR start "rule__FilterSpec__Group__6"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1796:1: rule__FilterSpec__Group__6 : rule__FilterSpec__Group__6__Impl rule__FilterSpec__Group__7 ;
    public final void rule__FilterSpec__Group__6() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1800:1: ( rule__FilterSpec__Group__6__Impl rule__FilterSpec__Group__7 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1801:2: rule__FilterSpec__Group__6__Impl rule__FilterSpec__Group__7
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__6__Impl_in_rule__FilterSpec__Group__63785);
            rule__FilterSpec__Group__6__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__7_in_rule__FilterSpec__Group__63788);
            rule__FilterSpec__Group__7();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__6"


    // $ANTLR start "rule__FilterSpec__Group__6__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1808:1: rule__FilterSpec__Group__6__Impl : ( ( rule__FilterSpec__Group_6__0 )? ) ;
    public final void rule__FilterSpec__Group__6__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1812:1: ( ( ( rule__FilterSpec__Group_6__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1813:1: ( ( rule__FilterSpec__Group_6__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1813:1: ( ( rule__FilterSpec__Group_6__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1814:1: ( rule__FilterSpec__Group_6__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_6()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1815:1: ( rule__FilterSpec__Group_6__0 )?
            int alt12=2;
            int LA12_0 = input.LA(1);

            if ( (LA12_0==41) ) {
                alt12=1;
            }
            switch (alt12) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1815:2: rule__FilterSpec__Group_6__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_6__0_in_rule__FilterSpec__Group__6__Impl3815);
                    rule__FilterSpec__Group_6__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_6()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__6__Impl"


    // $ANTLR start "rule__FilterSpec__Group__7"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1825:1: rule__FilterSpec__Group__7 : rule__FilterSpec__Group__7__Impl rule__FilterSpec__Group__8 ;
    public final void rule__FilterSpec__Group__7() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1829:1: ( rule__FilterSpec__Group__7__Impl rule__FilterSpec__Group__8 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1830:2: rule__FilterSpec__Group__7__Impl rule__FilterSpec__Group__8
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__7__Impl_in_rule__FilterSpec__Group__73846);
            rule__FilterSpec__Group__7__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__8_in_rule__FilterSpec__Group__73849);
            rule__FilterSpec__Group__8();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__7"


    // $ANTLR start "rule__FilterSpec__Group__7__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1837:1: rule__FilterSpec__Group__7__Impl : ( ( rule__FilterSpec__Group_7__0 )? ) ;
    public final void rule__FilterSpec__Group__7__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1841:1: ( ( ( rule__FilterSpec__Group_7__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1842:1: ( ( rule__FilterSpec__Group_7__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1842:1: ( ( rule__FilterSpec__Group_7__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1843:1: ( rule__FilterSpec__Group_7__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_7()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1844:1: ( rule__FilterSpec__Group_7__0 )?
            int alt13=2;
            int LA13_0 = input.LA(1);

            if ( (LA13_0==42) ) {
                alt13=1;
            }
            switch (alt13) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1844:2: rule__FilterSpec__Group_7__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_7__0_in_rule__FilterSpec__Group__7__Impl3876);
                    rule__FilterSpec__Group_7__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_7()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__7__Impl"


    // $ANTLR start "rule__FilterSpec__Group__8"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1854:1: rule__FilterSpec__Group__8 : rule__FilterSpec__Group__8__Impl rule__FilterSpec__Group__9 ;
    public final void rule__FilterSpec__Group__8() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1858:1: ( rule__FilterSpec__Group__8__Impl rule__FilterSpec__Group__9 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1859:2: rule__FilterSpec__Group__8__Impl rule__FilterSpec__Group__9
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__8__Impl_in_rule__FilterSpec__Group__83907);
            rule__FilterSpec__Group__8__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__9_in_rule__FilterSpec__Group__83910);
            rule__FilterSpec__Group__9();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__8"


    // $ANTLR start "rule__FilterSpec__Group__8__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1866:1: rule__FilterSpec__Group__8__Impl : ( ( rule__FilterSpec__Group_8__0 )? ) ;
    public final void rule__FilterSpec__Group__8__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1870:1: ( ( ( rule__FilterSpec__Group_8__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1871:1: ( ( rule__FilterSpec__Group_8__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1871:1: ( ( rule__FilterSpec__Group_8__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1872:1: ( rule__FilterSpec__Group_8__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_8()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1873:1: ( rule__FilterSpec__Group_8__0 )?
            int alt14=2;
            int LA14_0 = input.LA(1);

            if ( (LA14_0==43) ) {
                alt14=1;
            }
            switch (alt14) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1873:2: rule__FilterSpec__Group_8__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_8__0_in_rule__FilterSpec__Group__8__Impl3937);
                    rule__FilterSpec__Group_8__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_8()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__8__Impl"


    // $ANTLR start "rule__FilterSpec__Group__9"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1883:1: rule__FilterSpec__Group__9 : rule__FilterSpec__Group__9__Impl rule__FilterSpec__Group__10 ;
    public final void rule__FilterSpec__Group__9() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1887:1: ( rule__FilterSpec__Group__9__Impl rule__FilterSpec__Group__10 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1888:2: rule__FilterSpec__Group__9__Impl rule__FilterSpec__Group__10
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__9__Impl_in_rule__FilterSpec__Group__93968);
            rule__FilterSpec__Group__9__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__10_in_rule__FilterSpec__Group__93971);
            rule__FilterSpec__Group__10();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__9"


    // $ANTLR start "rule__FilterSpec__Group__9__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1895:1: rule__FilterSpec__Group__9__Impl : ( ( rule__FilterSpec__NegAssignment_9 )? ) ;
    public final void rule__FilterSpec__Group__9__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1899:1: ( ( ( rule__FilterSpec__NegAssignment_9 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1900:1: ( ( rule__FilterSpec__NegAssignment_9 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1900:1: ( ( rule__FilterSpec__NegAssignment_9 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1901:1: ( rule__FilterSpec__NegAssignment_9 )?
            {
             before(grammarAccess.getFilterSpecAccess().getNegAssignment_9()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1902:1: ( rule__FilterSpec__NegAssignment_9 )?
            int alt15=2;
            int LA15_0 = input.LA(1);

            if ( (LA15_0==55) ) {
                alt15=1;
            }
            switch (alt15) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1902:2: rule__FilterSpec__NegAssignment_9
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__NegAssignment_9_in_rule__FilterSpec__Group__9__Impl3998);
                    rule__FilterSpec__NegAssignment_9();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getNegAssignment_9()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__9__Impl"


    // $ANTLR start "rule__FilterSpec__Group__10"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1912:1: rule__FilterSpec__Group__10 : rule__FilterSpec__Group__10__Impl rule__FilterSpec__Group__11 ;
    public final void rule__FilterSpec__Group__10() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1916:1: ( rule__FilterSpec__Group__10__Impl rule__FilterSpec__Group__11 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1917:2: rule__FilterSpec__Group__10__Impl rule__FilterSpec__Group__11
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__10__Impl_in_rule__FilterSpec__Group__104029);
            rule__FilterSpec__Group__10__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__11_in_rule__FilterSpec__Group__104032);
            rule__FilterSpec__Group__11();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__10"


    // $ANTLR start "rule__FilterSpec__Group__10__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1924:1: rule__FilterSpec__Group__10__Impl : ( ( rule__FilterSpec__SynAssignment_10 )? ) ;
    public final void rule__FilterSpec__Group__10__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1928:1: ( ( ( rule__FilterSpec__SynAssignment_10 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1929:1: ( ( rule__FilterSpec__SynAssignment_10 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1929:1: ( ( rule__FilterSpec__SynAssignment_10 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1930:1: ( rule__FilterSpec__SynAssignment_10 )?
            {
             before(grammarAccess.getFilterSpecAccess().getSynAssignment_10()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1931:1: ( rule__FilterSpec__SynAssignment_10 )?
            int alt16=2;
            int LA16_0 = input.LA(1);

            if ( (LA16_0==56) ) {
                alt16=1;
            }
            switch (alt16) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1931:2: rule__FilterSpec__SynAssignment_10
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__SynAssignment_10_in_rule__FilterSpec__Group__10__Impl4059);
                    rule__FilterSpec__SynAssignment_10();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getSynAssignment_10()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__10__Impl"


    // $ANTLR start "rule__FilterSpec__Group__11"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1941:1: rule__FilterSpec__Group__11 : rule__FilterSpec__Group__11__Impl rule__FilterSpec__Group__12 ;
    public final void rule__FilterSpec__Group__11() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1945:1: ( rule__FilterSpec__Group__11__Impl rule__FilterSpec__Group__12 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1946:2: rule__FilterSpec__Group__11__Impl rule__FilterSpec__Group__12
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__11__Impl_in_rule__FilterSpec__Group__114090);
            rule__FilterSpec__Group__11__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__12_in_rule__FilterSpec__Group__114093);
            rule__FilterSpec__Group__12();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__11"


    // $ANTLR start "rule__FilterSpec__Group__11__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1953:1: rule__FilterSpec__Group__11__Impl : ( ( rule__FilterSpec__Group_11__0 )? ) ;
    public final void rule__FilterSpec__Group__11__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1957:1: ( ( ( rule__FilterSpec__Group_11__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1958:1: ( ( rule__FilterSpec__Group_11__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1958:1: ( ( rule__FilterSpec__Group_11__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1959:1: ( rule__FilterSpec__Group_11__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_11()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1960:1: ( rule__FilterSpec__Group_11__0 )?
            int alt17=2;
            int LA17_0 = input.LA(1);

            if ( (LA17_0==44) ) {
                alt17=1;
            }
            switch (alt17) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1960:2: rule__FilterSpec__Group_11__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_11__0_in_rule__FilterSpec__Group__11__Impl4120);
                    rule__FilterSpec__Group_11__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_11()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__11__Impl"


    // $ANTLR start "rule__FilterSpec__Group__12"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1970:1: rule__FilterSpec__Group__12 : rule__FilterSpec__Group__12__Impl rule__FilterSpec__Group__13 ;
    public final void rule__FilterSpec__Group__12() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1974:1: ( rule__FilterSpec__Group__12__Impl rule__FilterSpec__Group__13 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1975:2: rule__FilterSpec__Group__12__Impl rule__FilterSpec__Group__13
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__12__Impl_in_rule__FilterSpec__Group__124151);
            rule__FilterSpec__Group__12__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__13_in_rule__FilterSpec__Group__124154);
            rule__FilterSpec__Group__13();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__12"


    // $ANTLR start "rule__FilterSpec__Group__12__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1982:1: rule__FilterSpec__Group__12__Impl : ( ( rule__FilterSpec__Group_12__0 )? ) ;
    public final void rule__FilterSpec__Group__12__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1986:1: ( ( ( rule__FilterSpec__Group_12__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1987:1: ( ( rule__FilterSpec__Group_12__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1987:1: ( ( rule__FilterSpec__Group_12__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1988:1: ( rule__FilterSpec__Group_12__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_12()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1989:1: ( rule__FilterSpec__Group_12__0 )?
            int alt18=2;
            int LA18_0 = input.LA(1);

            if ( (LA18_0==45) ) {
                alt18=1;
            }
            switch (alt18) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1989:2: rule__FilterSpec__Group_12__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_12__0_in_rule__FilterSpec__Group__12__Impl4181);
                    rule__FilterSpec__Group_12__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_12()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__12__Impl"


    // $ANTLR start "rule__FilterSpec__Group__13"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:1999:1: rule__FilterSpec__Group__13 : rule__FilterSpec__Group__13__Impl rule__FilterSpec__Group__14 ;
    public final void rule__FilterSpec__Group__13() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2003:1: ( rule__FilterSpec__Group__13__Impl rule__FilterSpec__Group__14 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2004:2: rule__FilterSpec__Group__13__Impl rule__FilterSpec__Group__14
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__13__Impl_in_rule__FilterSpec__Group__134212);
            rule__FilterSpec__Group__13__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__14_in_rule__FilterSpec__Group__134215);
            rule__FilterSpec__Group__14();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__13"


    // $ANTLR start "rule__FilterSpec__Group__13__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2011:1: rule__FilterSpec__Group__13__Impl : ( ( rule__FilterSpec__Group_13__0 )? ) ;
    public final void rule__FilterSpec__Group__13__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2015:1: ( ( ( rule__FilterSpec__Group_13__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2016:1: ( ( rule__FilterSpec__Group_13__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2016:1: ( ( rule__FilterSpec__Group_13__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2017:1: ( rule__FilterSpec__Group_13__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_13()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2018:1: ( rule__FilterSpec__Group_13__0 )?
            int alt19=2;
            int LA19_0 = input.LA(1);

            if ( (LA19_0==47) ) {
                alt19=1;
            }
            switch (alt19) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2018:2: rule__FilterSpec__Group_13__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_13__0_in_rule__FilterSpec__Group__13__Impl4242);
                    rule__FilterSpec__Group_13__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_13()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__13__Impl"


    // $ANTLR start "rule__FilterSpec__Group__14"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2028:1: rule__FilterSpec__Group__14 : rule__FilterSpec__Group__14__Impl rule__FilterSpec__Group__15 ;
    public final void rule__FilterSpec__Group__14() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2032:1: ( rule__FilterSpec__Group__14__Impl rule__FilterSpec__Group__15 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2033:2: rule__FilterSpec__Group__14__Impl rule__FilterSpec__Group__15
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__14__Impl_in_rule__FilterSpec__Group__144273);
            rule__FilterSpec__Group__14__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__15_in_rule__FilterSpec__Group__144276);
            rule__FilterSpec__Group__15();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__14"


    // $ANTLR start "rule__FilterSpec__Group__14__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2040:1: rule__FilterSpec__Group__14__Impl : ( ( rule__FilterSpec__Group_14__0 )? ) ;
    public final void rule__FilterSpec__Group__14__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2044:1: ( ( ( rule__FilterSpec__Group_14__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2045:1: ( ( rule__FilterSpec__Group_14__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2045:1: ( ( rule__FilterSpec__Group_14__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2046:1: ( rule__FilterSpec__Group_14__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_14()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2047:1: ( rule__FilterSpec__Group_14__0 )?
            int alt20=2;
            int LA20_0 = input.LA(1);

            if ( (LA20_0==48) ) {
                alt20=1;
            }
            switch (alt20) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2047:2: rule__FilterSpec__Group_14__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_14__0_in_rule__FilterSpec__Group__14__Impl4303);
                    rule__FilterSpec__Group_14__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_14()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__14__Impl"


    // $ANTLR start "rule__FilterSpec__Group__15"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2057:1: rule__FilterSpec__Group__15 : rule__FilterSpec__Group__15__Impl rule__FilterSpec__Group__16 ;
    public final void rule__FilterSpec__Group__15() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2061:1: ( rule__FilterSpec__Group__15__Impl rule__FilterSpec__Group__16 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2062:2: rule__FilterSpec__Group__15__Impl rule__FilterSpec__Group__16
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__15__Impl_in_rule__FilterSpec__Group__154334);
            rule__FilterSpec__Group__15__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__16_in_rule__FilterSpec__Group__154337);
            rule__FilterSpec__Group__16();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__15"


    // $ANTLR start "rule__FilterSpec__Group__15__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2069:1: rule__FilterSpec__Group__15__Impl : ( ( rule__FilterSpec__Group_15__0 )? ) ;
    public final void rule__FilterSpec__Group__15__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2073:1: ( ( ( rule__FilterSpec__Group_15__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2074:1: ( ( rule__FilterSpec__Group_15__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2074:1: ( ( rule__FilterSpec__Group_15__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2075:1: ( rule__FilterSpec__Group_15__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_15()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2076:1: ( rule__FilterSpec__Group_15__0 )?
            int alt21=2;
            int LA21_0 = input.LA(1);

            if ( (LA21_0==49) ) {
                alt21=1;
            }
            switch (alt21) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2076:2: rule__FilterSpec__Group_15__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_15__0_in_rule__FilterSpec__Group__15__Impl4364);
                    rule__FilterSpec__Group_15__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_15()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__15__Impl"


    // $ANTLR start "rule__FilterSpec__Group__16"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2086:1: rule__FilterSpec__Group__16 : rule__FilterSpec__Group__16__Impl rule__FilterSpec__Group__17 ;
    public final void rule__FilterSpec__Group__16() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2090:1: ( rule__FilterSpec__Group__16__Impl rule__FilterSpec__Group__17 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2091:2: rule__FilterSpec__Group__16__Impl rule__FilterSpec__Group__17
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__16__Impl_in_rule__FilterSpec__Group__164395);
            rule__FilterSpec__Group__16__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__17_in_rule__FilterSpec__Group__164398);
            rule__FilterSpec__Group__17();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__16"


    // $ANTLR start "rule__FilterSpec__Group__16__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2098:1: rule__FilterSpec__Group__16__Impl : ( ( rule__FilterSpec__Group_16__0 )? ) ;
    public final void rule__FilterSpec__Group__16__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2102:1: ( ( ( rule__FilterSpec__Group_16__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2103:1: ( ( rule__FilterSpec__Group_16__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2103:1: ( ( rule__FilterSpec__Group_16__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2104:1: ( rule__FilterSpec__Group_16__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_16()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2105:1: ( rule__FilterSpec__Group_16__0 )?
            int alt22=2;
            int LA22_0 = input.LA(1);

            if ( (LA22_0==50) ) {
                alt22=1;
            }
            switch (alt22) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2105:2: rule__FilterSpec__Group_16__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_16__0_in_rule__FilterSpec__Group__16__Impl4425);
                    rule__FilterSpec__Group_16__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_16()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__16__Impl"


    // $ANTLR start "rule__FilterSpec__Group__17"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2115:1: rule__FilterSpec__Group__17 : rule__FilterSpec__Group__17__Impl rule__FilterSpec__Group__18 ;
    public final void rule__FilterSpec__Group__17() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2119:1: ( rule__FilterSpec__Group__17__Impl rule__FilterSpec__Group__18 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2120:2: rule__FilterSpec__Group__17__Impl rule__FilterSpec__Group__18
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__17__Impl_in_rule__FilterSpec__Group__174456);
            rule__FilterSpec__Group__17__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__18_in_rule__FilterSpec__Group__174459);
            rule__FilterSpec__Group__18();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__17"


    // $ANTLR start "rule__FilterSpec__Group__17__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2127:1: rule__FilterSpec__Group__17__Impl : ( ( '-j' )? ) ;
    public final void rule__FilterSpec__Group__17__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2131:1: ( ( ( '-j' )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2132:1: ( ( '-j' )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2132:1: ( ( '-j' )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2133:1: ( '-j' )?
            {
             before(grammarAccess.getFilterSpecAccess().getJKeyword_17()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2134:1: ( '-j' )?
            int alt23=2;
            int LA23_0 = input.LA(1);

            if ( (LA23_0==37) ) {
                alt23=1;
            }
            switch (alt23) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2135:2: '-j'
                    {
                    match(input,37,FOLLOW_37_in_rule__FilterSpec__Group__17__Impl4488); 

                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getJKeyword_17()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__17__Impl"


    // $ANTLR start "rule__FilterSpec__Group__18"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2146:1: rule__FilterSpec__Group__18 : rule__FilterSpec__Group__18__Impl rule__FilterSpec__Group__19 ;
    public final void rule__FilterSpec__Group__18() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2150:1: ( rule__FilterSpec__Group__18__Impl rule__FilterSpec__Group__19 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2151:2: rule__FilterSpec__Group__18__Impl rule__FilterSpec__Group__19
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__18__Impl_in_rule__FilterSpec__Group__184521);
            rule__FilterSpec__Group__18__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group__19_in_rule__FilterSpec__Group__184524);
            rule__FilterSpec__Group__19();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__18"


    // $ANTLR start "rule__FilterSpec__Group__18__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2158:1: rule__FilterSpec__Group__18__Impl : ( ( rule__FilterSpec__TargetAssignment_18 ) ) ;
    public final void rule__FilterSpec__Group__18__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2162:1: ( ( ( rule__FilterSpec__TargetAssignment_18 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2163:1: ( ( rule__FilterSpec__TargetAssignment_18 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2163:1: ( ( rule__FilterSpec__TargetAssignment_18 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2164:1: ( rule__FilterSpec__TargetAssignment_18 )
            {
             before(grammarAccess.getFilterSpecAccess().getTargetAssignment_18()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2165:1: ( rule__FilterSpec__TargetAssignment_18 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2165:2: rule__FilterSpec__TargetAssignment_18
            {
            pushFollow(FOLLOW_rule__FilterSpec__TargetAssignment_18_in_rule__FilterSpec__Group__18__Impl4551);
            rule__FilterSpec__TargetAssignment_18();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getTargetAssignment_18()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__18__Impl"


    // $ANTLR start "rule__FilterSpec__Group__19"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2175:1: rule__FilterSpec__Group__19 : rule__FilterSpec__Group__19__Impl ;
    public final void rule__FilterSpec__Group__19() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2179:1: ( rule__FilterSpec__Group__19__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2180:2: rule__FilterSpec__Group__19__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group__19__Impl_in_rule__FilterSpec__Group__194581);
            rule__FilterSpec__Group__19__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__19"


    // $ANTLR start "rule__FilterSpec__Group__19__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2186:1: rule__FilterSpec__Group__19__Impl : ( ( rule__FilterSpec__Group_19__0 )? ) ;
    public final void rule__FilterSpec__Group__19__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2190:1: ( ( ( rule__FilterSpec__Group_19__0 )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2191:1: ( ( rule__FilterSpec__Group_19__0 )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2191:1: ( ( rule__FilterSpec__Group_19__0 )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2192:1: ( rule__FilterSpec__Group_19__0 )?
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_19()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2193:1: ( rule__FilterSpec__Group_19__0 )?
            int alt24=2;
            int LA24_0 = input.LA(1);

            if ( (LA24_0==51) ) {
                alt24=1;
            }
            switch (alt24) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2193:2: rule__FilterSpec__Group_19__0
                    {
                    pushFollow(FOLLOW_rule__FilterSpec__Group_19__0_in_rule__FilterSpec__Group__19__Impl4608);
                    rule__FilterSpec__Group_19__0();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getFilterSpecAccess().getGroup_19()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group__19__Impl"


    // $ANTLR start "rule__FilterSpec__Group_3__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2243:1: rule__FilterSpec__Group_3__0 : rule__FilterSpec__Group_3__0__Impl rule__FilterSpec__Group_3__1 ;
    public final void rule__FilterSpec__Group_3__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2247:1: ( rule__FilterSpec__Group_3__0__Impl rule__FilterSpec__Group_3__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2248:2: rule__FilterSpec__Group_3__0__Impl rule__FilterSpec__Group_3__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_3__0__Impl_in_rule__FilterSpec__Group_3__04679);
            rule__FilterSpec__Group_3__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_3__1_in_rule__FilterSpec__Group_3__04682);
            rule__FilterSpec__Group_3__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_3__0"


    // $ANTLR start "rule__FilterSpec__Group_3__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2255:1: rule__FilterSpec__Group_3__0__Impl : ( '-p' ) ;
    public final void rule__FilterSpec__Group_3__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2259:1: ( ( '-p' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2260:1: ( '-p' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2260:1: ( '-p' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2261:1: '-p'
            {
             before(grammarAccess.getFilterSpecAccess().getPKeyword_3_0()); 
            match(input,38,FOLLOW_38_in_rule__FilterSpec__Group_3__0__Impl4710); 
             after(grammarAccess.getFilterSpecAccess().getPKeyword_3_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_3__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_3__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2274:1: rule__FilterSpec__Group_3__1 : rule__FilterSpec__Group_3__1__Impl ;
    public final void rule__FilterSpec__Group_3__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2278:1: ( rule__FilterSpec__Group_3__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2279:2: rule__FilterSpec__Group_3__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_3__1__Impl_in_rule__FilterSpec__Group_3__14741);
            rule__FilterSpec__Group_3__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_3__1"


    // $ANTLR start "rule__FilterSpec__Group_3__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2285:1: rule__FilterSpec__Group_3__1__Impl : ( ( rule__FilterSpec__ProtocolAssignment_3_1 ) ) ;
    public final void rule__FilterSpec__Group_3__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2289:1: ( ( ( rule__FilterSpec__ProtocolAssignment_3_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2290:1: ( ( rule__FilterSpec__ProtocolAssignment_3_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2290:1: ( ( rule__FilterSpec__ProtocolAssignment_3_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2291:1: ( rule__FilterSpec__ProtocolAssignment_3_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getProtocolAssignment_3_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2292:1: ( rule__FilterSpec__ProtocolAssignment_3_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2292:2: rule__FilterSpec__ProtocolAssignment_3_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__ProtocolAssignment_3_1_in_rule__FilterSpec__Group_3__1__Impl4768);
            rule__FilterSpec__ProtocolAssignment_3_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getProtocolAssignment_3_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_3__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_4__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2306:1: rule__FilterSpec__Group_4__0 : rule__FilterSpec__Group_4__0__Impl rule__FilterSpec__Group_4__1 ;
    public final void rule__FilterSpec__Group_4__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2310:1: ( rule__FilterSpec__Group_4__0__Impl rule__FilterSpec__Group_4__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2311:2: rule__FilterSpec__Group_4__0__Impl rule__FilterSpec__Group_4__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_4__0__Impl_in_rule__FilterSpec__Group_4__04802);
            rule__FilterSpec__Group_4__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_4__1_in_rule__FilterSpec__Group_4__04805);
            rule__FilterSpec__Group_4__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_4__0"


    // $ANTLR start "rule__FilterSpec__Group_4__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2318:1: rule__FilterSpec__Group_4__0__Impl : ( '-s' ) ;
    public final void rule__FilterSpec__Group_4__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2322:1: ( ( '-s' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2323:1: ( '-s' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2323:1: ( '-s' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2324:1: '-s'
            {
             before(grammarAccess.getFilterSpecAccess().getSKeyword_4_0()); 
            match(input,39,FOLLOW_39_in_rule__FilterSpec__Group_4__0__Impl4833); 
             after(grammarAccess.getFilterSpecAccess().getSKeyword_4_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_4__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_4__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2337:1: rule__FilterSpec__Group_4__1 : rule__FilterSpec__Group_4__1__Impl ;
    public final void rule__FilterSpec__Group_4__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2341:1: ( rule__FilterSpec__Group_4__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2342:2: rule__FilterSpec__Group_4__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_4__1__Impl_in_rule__FilterSpec__Group_4__14864);
            rule__FilterSpec__Group_4__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_4__1"


    // $ANTLR start "rule__FilterSpec__Group_4__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2348:1: rule__FilterSpec__Group_4__1__Impl : ( ( rule__FilterSpec__IpAssignment_4_1 ) ) ;
    public final void rule__FilterSpec__Group_4__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2352:1: ( ( ( rule__FilterSpec__IpAssignment_4_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2353:1: ( ( rule__FilterSpec__IpAssignment_4_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2353:1: ( ( rule__FilterSpec__IpAssignment_4_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2354:1: ( rule__FilterSpec__IpAssignment_4_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getIpAssignment_4_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2355:1: ( rule__FilterSpec__IpAssignment_4_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2355:2: rule__FilterSpec__IpAssignment_4_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__IpAssignment_4_1_in_rule__FilterSpec__Group_4__1__Impl4891);
            rule__FilterSpec__IpAssignment_4_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getIpAssignment_4_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_4__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_5__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2369:1: rule__FilterSpec__Group_5__0 : rule__FilterSpec__Group_5__0__Impl rule__FilterSpec__Group_5__1 ;
    public final void rule__FilterSpec__Group_5__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2373:1: ( rule__FilterSpec__Group_5__0__Impl rule__FilterSpec__Group_5__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2374:2: rule__FilterSpec__Group_5__0__Impl rule__FilterSpec__Group_5__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_5__0__Impl_in_rule__FilterSpec__Group_5__04925);
            rule__FilterSpec__Group_5__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_5__1_in_rule__FilterSpec__Group_5__04928);
            rule__FilterSpec__Group_5__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_5__0"


    // $ANTLR start "rule__FilterSpec__Group_5__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2381:1: rule__FilterSpec__Group_5__0__Impl : ( '-i' ) ;
    public final void rule__FilterSpec__Group_5__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2385:1: ( ( '-i' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2386:1: ( '-i' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2386:1: ( '-i' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2387:1: '-i'
            {
             before(grammarAccess.getFilterSpecAccess().getIKeyword_5_0()); 
            match(input,40,FOLLOW_40_in_rule__FilterSpec__Group_5__0__Impl4956); 
             after(grammarAccess.getFilterSpecAccess().getIKeyword_5_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_5__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_5__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2400:1: rule__FilterSpec__Group_5__1 : rule__FilterSpec__Group_5__1__Impl ;
    public final void rule__FilterSpec__Group_5__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2404:1: ( rule__FilterSpec__Group_5__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2405:2: rule__FilterSpec__Group_5__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_5__1__Impl_in_rule__FilterSpec__Group_5__14987);
            rule__FilterSpec__Group_5__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_5__1"


    // $ANTLR start "rule__FilterSpec__Group_5__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2411:1: rule__FilterSpec__Group_5__1__Impl : ( ( rule__FilterSpec__InterfaceAssignment_5_1 ) ) ;
    public final void rule__FilterSpec__Group_5__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2415:1: ( ( ( rule__FilterSpec__InterfaceAssignment_5_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2416:1: ( ( rule__FilterSpec__InterfaceAssignment_5_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2416:1: ( ( rule__FilterSpec__InterfaceAssignment_5_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2417:1: ( rule__FilterSpec__InterfaceAssignment_5_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getInterfaceAssignment_5_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2418:1: ( rule__FilterSpec__InterfaceAssignment_5_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2418:2: rule__FilterSpec__InterfaceAssignment_5_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__InterfaceAssignment_5_1_in_rule__FilterSpec__Group_5__1__Impl5014);
            rule__FilterSpec__InterfaceAssignment_5_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getInterfaceAssignment_5_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_5__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_6__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2432:1: rule__FilterSpec__Group_6__0 : rule__FilterSpec__Group_6__0__Impl rule__FilterSpec__Group_6__1 ;
    public final void rule__FilterSpec__Group_6__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2436:1: ( rule__FilterSpec__Group_6__0__Impl rule__FilterSpec__Group_6__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2437:2: rule__FilterSpec__Group_6__0__Impl rule__FilterSpec__Group_6__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_6__0__Impl_in_rule__FilterSpec__Group_6__05048);
            rule__FilterSpec__Group_6__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_6__1_in_rule__FilterSpec__Group_6__05051);
            rule__FilterSpec__Group_6__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_6__0"


    // $ANTLR start "rule__FilterSpec__Group_6__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2444:1: rule__FilterSpec__Group_6__0__Impl : ( '-d' ) ;
    public final void rule__FilterSpec__Group_6__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2448:1: ( ( '-d' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2449:1: ( '-d' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2449:1: ( '-d' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2450:1: '-d'
            {
             before(grammarAccess.getFilterSpecAccess().getDKeyword_6_0()); 
            match(input,41,FOLLOW_41_in_rule__FilterSpec__Group_6__0__Impl5079); 
             after(grammarAccess.getFilterSpecAccess().getDKeyword_6_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_6__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_6__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2463:1: rule__FilterSpec__Group_6__1 : rule__FilterSpec__Group_6__1__Impl ;
    public final void rule__FilterSpec__Group_6__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2467:1: ( rule__FilterSpec__Group_6__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2468:2: rule__FilterSpec__Group_6__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_6__1__Impl_in_rule__FilterSpec__Group_6__15110);
            rule__FilterSpec__Group_6__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_6__1"


    // $ANTLR start "rule__FilterSpec__Group_6__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2474:1: rule__FilterSpec__Group_6__1__Impl : ( ( rule__FilterSpec__IpDstAssignment_6_1 ) ) ;
    public final void rule__FilterSpec__Group_6__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2478:1: ( ( ( rule__FilterSpec__IpDstAssignment_6_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2479:1: ( ( rule__FilterSpec__IpDstAssignment_6_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2479:1: ( ( rule__FilterSpec__IpDstAssignment_6_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2480:1: ( rule__FilterSpec__IpDstAssignment_6_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getIpDstAssignment_6_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2481:1: ( rule__FilterSpec__IpDstAssignment_6_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2481:2: rule__FilterSpec__IpDstAssignment_6_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__IpDstAssignment_6_1_in_rule__FilterSpec__Group_6__1__Impl5137);
            rule__FilterSpec__IpDstAssignment_6_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getIpDstAssignment_6_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_6__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_7__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2495:1: rule__FilterSpec__Group_7__0 : rule__FilterSpec__Group_7__0__Impl rule__FilterSpec__Group_7__1 ;
    public final void rule__FilterSpec__Group_7__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2499:1: ( rule__FilterSpec__Group_7__0__Impl rule__FilterSpec__Group_7__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2500:2: rule__FilterSpec__Group_7__0__Impl rule__FilterSpec__Group_7__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_7__0__Impl_in_rule__FilterSpec__Group_7__05171);
            rule__FilterSpec__Group_7__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_7__1_in_rule__FilterSpec__Group_7__05174);
            rule__FilterSpec__Group_7__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_7__0"


    // $ANTLR start "rule__FilterSpec__Group_7__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2507:1: rule__FilterSpec__Group_7__0__Impl : ( '--sport' ) ;
    public final void rule__FilterSpec__Group_7__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2511:1: ( ( '--sport' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2512:1: ( '--sport' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2512:1: ( '--sport' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2513:1: '--sport'
            {
             before(grammarAccess.getFilterSpecAccess().getSportKeyword_7_0()); 
            match(input,42,FOLLOW_42_in_rule__FilterSpec__Group_7__0__Impl5202); 
             after(grammarAccess.getFilterSpecAccess().getSportKeyword_7_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_7__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_7__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2526:1: rule__FilterSpec__Group_7__1 : rule__FilterSpec__Group_7__1__Impl ;
    public final void rule__FilterSpec__Group_7__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2530:1: ( rule__FilterSpec__Group_7__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2531:2: rule__FilterSpec__Group_7__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_7__1__Impl_in_rule__FilterSpec__Group_7__15233);
            rule__FilterSpec__Group_7__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_7__1"


    // $ANTLR start "rule__FilterSpec__Group_7__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2537:1: rule__FilterSpec__Group_7__1__Impl : ( ( rule__FilterSpec__SourcePortAssignment_7_1 ) ) ;
    public final void rule__FilterSpec__Group_7__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2541:1: ( ( ( rule__FilterSpec__SourcePortAssignment_7_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2542:1: ( ( rule__FilterSpec__SourcePortAssignment_7_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2542:1: ( ( rule__FilterSpec__SourcePortAssignment_7_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2543:1: ( rule__FilterSpec__SourcePortAssignment_7_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getSourcePortAssignment_7_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2544:1: ( rule__FilterSpec__SourcePortAssignment_7_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2544:2: rule__FilterSpec__SourcePortAssignment_7_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__SourcePortAssignment_7_1_in_rule__FilterSpec__Group_7__1__Impl5260);
            rule__FilterSpec__SourcePortAssignment_7_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getSourcePortAssignment_7_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_7__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_8__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2558:1: rule__FilterSpec__Group_8__0 : rule__FilterSpec__Group_8__0__Impl rule__FilterSpec__Group_8__1 ;
    public final void rule__FilterSpec__Group_8__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2562:1: ( rule__FilterSpec__Group_8__0__Impl rule__FilterSpec__Group_8__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2563:2: rule__FilterSpec__Group_8__0__Impl rule__FilterSpec__Group_8__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_8__0__Impl_in_rule__FilterSpec__Group_8__05294);
            rule__FilterSpec__Group_8__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_8__1_in_rule__FilterSpec__Group_8__05297);
            rule__FilterSpec__Group_8__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_8__0"


    // $ANTLR start "rule__FilterSpec__Group_8__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2570:1: rule__FilterSpec__Group_8__0__Impl : ( '--dport' ) ;
    public final void rule__FilterSpec__Group_8__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2574:1: ( ( '--dport' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2575:1: ( '--dport' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2575:1: ( '--dport' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2576:1: '--dport'
            {
             before(grammarAccess.getFilterSpecAccess().getDportKeyword_8_0()); 
            match(input,43,FOLLOW_43_in_rule__FilterSpec__Group_8__0__Impl5325); 
             after(grammarAccess.getFilterSpecAccess().getDportKeyword_8_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_8__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_8__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2589:1: rule__FilterSpec__Group_8__1 : rule__FilterSpec__Group_8__1__Impl ;
    public final void rule__FilterSpec__Group_8__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2593:1: ( rule__FilterSpec__Group_8__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2594:2: rule__FilterSpec__Group_8__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_8__1__Impl_in_rule__FilterSpec__Group_8__15356);
            rule__FilterSpec__Group_8__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_8__1"


    // $ANTLR start "rule__FilterSpec__Group_8__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2600:1: rule__FilterSpec__Group_8__1__Impl : ( ( rule__FilterSpec__DestinationPortAssignment_8_1 ) ) ;
    public final void rule__FilterSpec__Group_8__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2604:1: ( ( ( rule__FilterSpec__DestinationPortAssignment_8_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2605:1: ( ( rule__FilterSpec__DestinationPortAssignment_8_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2605:1: ( ( rule__FilterSpec__DestinationPortAssignment_8_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2606:1: ( rule__FilterSpec__DestinationPortAssignment_8_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getDestinationPortAssignment_8_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2607:1: ( rule__FilterSpec__DestinationPortAssignment_8_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2607:2: rule__FilterSpec__DestinationPortAssignment_8_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__DestinationPortAssignment_8_1_in_rule__FilterSpec__Group_8__1__Impl5383);
            rule__FilterSpec__DestinationPortAssignment_8_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getDestinationPortAssignment_8_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_8__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_11__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2621:1: rule__FilterSpec__Group_11__0 : rule__FilterSpec__Group_11__0__Impl rule__FilterSpec__Group_11__1 ;
    public final void rule__FilterSpec__Group_11__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2625:1: ( rule__FilterSpec__Group_11__0__Impl rule__FilterSpec__Group_11__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2626:2: rule__FilterSpec__Group_11__0__Impl rule__FilterSpec__Group_11__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_11__0__Impl_in_rule__FilterSpec__Group_11__05417);
            rule__FilterSpec__Group_11__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_11__1_in_rule__FilterSpec__Group_11__05420);
            rule__FilterSpec__Group_11__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_11__0"


    // $ANTLR start "rule__FilterSpec__Group_11__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2633:1: rule__FilterSpec__Group_11__0__Impl : ( '-m' ) ;
    public final void rule__FilterSpec__Group_11__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2637:1: ( ( '-m' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2638:1: ( '-m' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2638:1: ( '-m' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2639:1: '-m'
            {
             before(grammarAccess.getFilterSpecAccess().getMKeyword_11_0()); 
            match(input,44,FOLLOW_44_in_rule__FilterSpec__Group_11__0__Impl5448); 
             after(grammarAccess.getFilterSpecAccess().getMKeyword_11_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_11__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_11__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2652:1: rule__FilterSpec__Group_11__1 : rule__FilterSpec__Group_11__1__Impl ;
    public final void rule__FilterSpec__Group_11__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2656:1: ( rule__FilterSpec__Group_11__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2657:2: rule__FilterSpec__Group_11__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_11__1__Impl_in_rule__FilterSpec__Group_11__15479);
            rule__FilterSpec__Group_11__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_11__1"


    // $ANTLR start "rule__FilterSpec__Group_11__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2663:1: rule__FilterSpec__Group_11__1__Impl : ( ( rule__FilterSpec__MatchesAssignment_11_1 ) ) ;
    public final void rule__FilterSpec__Group_11__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2667:1: ( ( ( rule__FilterSpec__MatchesAssignment_11_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2668:1: ( ( rule__FilterSpec__MatchesAssignment_11_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2668:1: ( ( rule__FilterSpec__MatchesAssignment_11_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2669:1: ( rule__FilterSpec__MatchesAssignment_11_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getMatchesAssignment_11_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2670:1: ( rule__FilterSpec__MatchesAssignment_11_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2670:2: rule__FilterSpec__MatchesAssignment_11_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__MatchesAssignment_11_1_in_rule__FilterSpec__Group_11__1__Impl5506);
            rule__FilterSpec__MatchesAssignment_11_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getMatchesAssignment_11_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_11__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_12__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2684:1: rule__FilterSpec__Group_12__0 : rule__FilterSpec__Group_12__0__Impl rule__FilterSpec__Group_12__1 ;
    public final void rule__FilterSpec__Group_12__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2688:1: ( rule__FilterSpec__Group_12__0__Impl rule__FilterSpec__Group_12__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2689:2: rule__FilterSpec__Group_12__0__Impl rule__FilterSpec__Group_12__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_12__0__Impl_in_rule__FilterSpec__Group_12__05540);
            rule__FilterSpec__Group_12__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_12__1_in_rule__FilterSpec__Group_12__05543);
            rule__FilterSpec__Group_12__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__0"


    // $ANTLR start "rule__FilterSpec__Group_12__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2696:1: rule__FilterSpec__Group_12__0__Impl : ( '--ctstate' ) ;
    public final void rule__FilterSpec__Group_12__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2700:1: ( ( '--ctstate' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2701:1: ( '--ctstate' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2701:1: ( '--ctstate' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2702:1: '--ctstate'
            {
             before(grammarAccess.getFilterSpecAccess().getCtstateKeyword_12_0()); 
            match(input,45,FOLLOW_45_in_rule__FilterSpec__Group_12__0__Impl5571); 
             after(grammarAccess.getFilterSpecAccess().getCtstateKeyword_12_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_12__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2715:1: rule__FilterSpec__Group_12__1 : rule__FilterSpec__Group_12__1__Impl rule__FilterSpec__Group_12__2 ;
    public final void rule__FilterSpec__Group_12__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2719:1: ( rule__FilterSpec__Group_12__1__Impl rule__FilterSpec__Group_12__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2720:2: rule__FilterSpec__Group_12__1__Impl rule__FilterSpec__Group_12__2
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_12__1__Impl_in_rule__FilterSpec__Group_12__15602);
            rule__FilterSpec__Group_12__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_12__2_in_rule__FilterSpec__Group_12__15605);
            rule__FilterSpec__Group_12__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__1"


    // $ANTLR start "rule__FilterSpec__Group_12__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2727:1: rule__FilterSpec__Group_12__1__Impl : ( ( rule__FilterSpec__StatesAssignment_12_1 ) ) ;
    public final void rule__FilterSpec__Group_12__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2731:1: ( ( ( rule__FilterSpec__StatesAssignment_12_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2732:1: ( ( rule__FilterSpec__StatesAssignment_12_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2732:1: ( ( rule__FilterSpec__StatesAssignment_12_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2733:1: ( rule__FilterSpec__StatesAssignment_12_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getStatesAssignment_12_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2734:1: ( rule__FilterSpec__StatesAssignment_12_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2734:2: rule__FilterSpec__StatesAssignment_12_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__StatesAssignment_12_1_in_rule__FilterSpec__Group_12__1__Impl5632);
            rule__FilterSpec__StatesAssignment_12_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getStatesAssignment_12_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_12__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2744:1: rule__FilterSpec__Group_12__2 : rule__FilterSpec__Group_12__2__Impl ;
    public final void rule__FilterSpec__Group_12__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2748:1: ( rule__FilterSpec__Group_12__2__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2749:2: rule__FilterSpec__Group_12__2__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_12__2__Impl_in_rule__FilterSpec__Group_12__25662);
            rule__FilterSpec__Group_12__2__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__2"


    // $ANTLR start "rule__FilterSpec__Group_12__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2755:1: rule__FilterSpec__Group_12__2__Impl : ( ( rule__FilterSpec__Group_12_2__0 )* ) ;
    public final void rule__FilterSpec__Group_12__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2759:1: ( ( ( rule__FilterSpec__Group_12_2__0 )* ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2760:1: ( ( rule__FilterSpec__Group_12_2__0 )* )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2760:1: ( ( rule__FilterSpec__Group_12_2__0 )* )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2761:1: ( rule__FilterSpec__Group_12_2__0 )*
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_12_2()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2762:1: ( rule__FilterSpec__Group_12_2__0 )*
            loop25:
            do {
                int alt25=2;
                int LA25_0 = input.LA(1);

                if ( (LA25_0==46) ) {
                    alt25=1;
                }


                switch (alt25) {
            	case 1 :
            	    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2762:2: rule__FilterSpec__Group_12_2__0
            	    {
            	    pushFollow(FOLLOW_rule__FilterSpec__Group_12_2__0_in_rule__FilterSpec__Group_12__2__Impl5689);
            	    rule__FilterSpec__Group_12_2__0();

            	    state._fsp--;


            	    }
            	    break;

            	default :
            	    break loop25;
                }
            } while (true);

             after(grammarAccess.getFilterSpecAccess().getGroup_12_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12__2__Impl"


    // $ANTLR start "rule__FilterSpec__Group_12_2__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2778:1: rule__FilterSpec__Group_12_2__0 : rule__FilterSpec__Group_12_2__0__Impl rule__FilterSpec__Group_12_2__1 ;
    public final void rule__FilterSpec__Group_12_2__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2782:1: ( rule__FilterSpec__Group_12_2__0__Impl rule__FilterSpec__Group_12_2__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2783:2: rule__FilterSpec__Group_12_2__0__Impl rule__FilterSpec__Group_12_2__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_12_2__0__Impl_in_rule__FilterSpec__Group_12_2__05726);
            rule__FilterSpec__Group_12_2__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_12_2__1_in_rule__FilterSpec__Group_12_2__05729);
            rule__FilterSpec__Group_12_2__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12_2__0"


    // $ANTLR start "rule__FilterSpec__Group_12_2__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2790:1: rule__FilterSpec__Group_12_2__0__Impl : ( ',' ) ;
    public final void rule__FilterSpec__Group_12_2__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2794:1: ( ( ',' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2795:1: ( ',' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2795:1: ( ',' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2796:1: ','
            {
             before(grammarAccess.getFilterSpecAccess().getCommaKeyword_12_2_0()); 
            match(input,46,FOLLOW_46_in_rule__FilterSpec__Group_12_2__0__Impl5757); 
             after(grammarAccess.getFilterSpecAccess().getCommaKeyword_12_2_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12_2__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_12_2__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2809:1: rule__FilterSpec__Group_12_2__1 : rule__FilterSpec__Group_12_2__1__Impl ;
    public final void rule__FilterSpec__Group_12_2__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2813:1: ( rule__FilterSpec__Group_12_2__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2814:2: rule__FilterSpec__Group_12_2__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_12_2__1__Impl_in_rule__FilterSpec__Group_12_2__15788);
            rule__FilterSpec__Group_12_2__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12_2__1"


    // $ANTLR start "rule__FilterSpec__Group_12_2__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2820:1: rule__FilterSpec__Group_12_2__1__Impl : ( ( rule__FilterSpec__StatesAssignment_12_2_1 ) ) ;
    public final void rule__FilterSpec__Group_12_2__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2824:1: ( ( ( rule__FilterSpec__StatesAssignment_12_2_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2825:1: ( ( rule__FilterSpec__StatesAssignment_12_2_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2825:1: ( ( rule__FilterSpec__StatesAssignment_12_2_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2826:1: ( rule__FilterSpec__StatesAssignment_12_2_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getStatesAssignment_12_2_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2827:1: ( rule__FilterSpec__StatesAssignment_12_2_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2827:2: rule__FilterSpec__StatesAssignment_12_2_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__StatesAssignment_12_2_1_in_rule__FilterSpec__Group_12_2__1__Impl5815);
            rule__FilterSpec__StatesAssignment_12_2_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getStatesAssignment_12_2_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_12_2__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_13__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2841:1: rule__FilterSpec__Group_13__0 : rule__FilterSpec__Group_13__0__Impl rule__FilterSpec__Group_13__1 ;
    public final void rule__FilterSpec__Group_13__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2845:1: ( rule__FilterSpec__Group_13__0__Impl rule__FilterSpec__Group_13__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2846:2: rule__FilterSpec__Group_13__0__Impl rule__FilterSpec__Group_13__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_13__0__Impl_in_rule__FilterSpec__Group_13__05849);
            rule__FilterSpec__Group_13__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_13__1_in_rule__FilterSpec__Group_13__05852);
            rule__FilterSpec__Group_13__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_13__0"


    // $ANTLR start "rule__FilterSpec__Group_13__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2853:1: rule__FilterSpec__Group_13__0__Impl : ( '--ctdir' ) ;
    public final void rule__FilterSpec__Group_13__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2857:1: ( ( '--ctdir' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2858:1: ( '--ctdir' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2858:1: ( '--ctdir' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2859:1: '--ctdir'
            {
             before(grammarAccess.getFilterSpecAccess().getCtdirKeyword_13_0()); 
            match(input,47,FOLLOW_47_in_rule__FilterSpec__Group_13__0__Impl5880); 
             after(grammarAccess.getFilterSpecAccess().getCtdirKeyword_13_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_13__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_13__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2872:1: rule__FilterSpec__Group_13__1 : rule__FilterSpec__Group_13__1__Impl ;
    public final void rule__FilterSpec__Group_13__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2876:1: ( rule__FilterSpec__Group_13__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2877:2: rule__FilterSpec__Group_13__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_13__1__Impl_in_rule__FilterSpec__Group_13__15911);
            rule__FilterSpec__Group_13__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_13__1"


    // $ANTLR start "rule__FilterSpec__Group_13__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2883:1: rule__FilterSpec__Group_13__1__Impl : ( ( rule__FilterSpec__DirAssignment_13_1 ) ) ;
    public final void rule__FilterSpec__Group_13__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2887:1: ( ( ( rule__FilterSpec__DirAssignment_13_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2888:1: ( ( rule__FilterSpec__DirAssignment_13_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2888:1: ( ( rule__FilterSpec__DirAssignment_13_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2889:1: ( rule__FilterSpec__DirAssignment_13_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getDirAssignment_13_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2890:1: ( rule__FilterSpec__DirAssignment_13_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2890:2: rule__FilterSpec__DirAssignment_13_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__DirAssignment_13_1_in_rule__FilterSpec__Group_13__1__Impl5938);
            rule__FilterSpec__DirAssignment_13_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getDirAssignment_13_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_13__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_14__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2904:1: rule__FilterSpec__Group_14__0 : rule__FilterSpec__Group_14__0__Impl rule__FilterSpec__Group_14__1 ;
    public final void rule__FilterSpec__Group_14__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2908:1: ( rule__FilterSpec__Group_14__0__Impl rule__FilterSpec__Group_14__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2909:2: rule__FilterSpec__Group_14__0__Impl rule__FilterSpec__Group_14__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_14__0__Impl_in_rule__FilterSpec__Group_14__05972);
            rule__FilterSpec__Group_14__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_14__1_in_rule__FilterSpec__Group_14__05975);
            rule__FilterSpec__Group_14__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_14__0"


    // $ANTLR start "rule__FilterSpec__Group_14__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2916:1: rule__FilterSpec__Group_14__0__Impl : ( '--ctstatus' ) ;
    public final void rule__FilterSpec__Group_14__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2920:1: ( ( '--ctstatus' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2921:1: ( '--ctstatus' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2921:1: ( '--ctstatus' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2922:1: '--ctstatus'
            {
             before(grammarAccess.getFilterSpecAccess().getCtstatusKeyword_14_0()); 
            match(input,48,FOLLOW_48_in_rule__FilterSpec__Group_14__0__Impl6003); 
             after(grammarAccess.getFilterSpecAccess().getCtstatusKeyword_14_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_14__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_14__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2935:1: rule__FilterSpec__Group_14__1 : rule__FilterSpec__Group_14__1__Impl ;
    public final void rule__FilterSpec__Group_14__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2939:1: ( rule__FilterSpec__Group_14__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2940:2: rule__FilterSpec__Group_14__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_14__1__Impl_in_rule__FilterSpec__Group_14__16034);
            rule__FilterSpec__Group_14__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_14__1"


    // $ANTLR start "rule__FilterSpec__Group_14__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2946:1: rule__FilterSpec__Group_14__1__Impl : ( ( rule__FilterSpec__StatusAssignment_14_1 ) ) ;
    public final void rule__FilterSpec__Group_14__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2950:1: ( ( ( rule__FilterSpec__StatusAssignment_14_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2951:1: ( ( rule__FilterSpec__StatusAssignment_14_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2951:1: ( ( rule__FilterSpec__StatusAssignment_14_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2952:1: ( rule__FilterSpec__StatusAssignment_14_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getStatusAssignment_14_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2953:1: ( rule__FilterSpec__StatusAssignment_14_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2953:2: rule__FilterSpec__StatusAssignment_14_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__StatusAssignment_14_1_in_rule__FilterSpec__Group_14__1__Impl6061);
            rule__FilterSpec__StatusAssignment_14_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getStatusAssignment_14_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_14__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_15__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2967:1: rule__FilterSpec__Group_15__0 : rule__FilterSpec__Group_15__0__Impl rule__FilterSpec__Group_15__1 ;
    public final void rule__FilterSpec__Group_15__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2971:1: ( rule__FilterSpec__Group_15__0__Impl rule__FilterSpec__Group_15__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2972:2: rule__FilterSpec__Group_15__0__Impl rule__FilterSpec__Group_15__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_15__0__Impl_in_rule__FilterSpec__Group_15__06095);
            rule__FilterSpec__Group_15__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_15__1_in_rule__FilterSpec__Group_15__06098);
            rule__FilterSpec__Group_15__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__0"


    // $ANTLR start "rule__FilterSpec__Group_15__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2979:1: rule__FilterSpec__Group_15__0__Impl : ( '--state' ) ;
    public final void rule__FilterSpec__Group_15__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2983:1: ( ( '--state' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2984:1: ( '--state' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2984:1: ( '--state' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2985:1: '--state'
            {
             before(grammarAccess.getFilterSpecAccess().getStateKeyword_15_0()); 
            match(input,49,FOLLOW_49_in_rule__FilterSpec__Group_15__0__Impl6126); 
             after(grammarAccess.getFilterSpecAccess().getStateKeyword_15_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_15__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:2998:1: rule__FilterSpec__Group_15__1 : rule__FilterSpec__Group_15__1__Impl rule__FilterSpec__Group_15__2 ;
    public final void rule__FilterSpec__Group_15__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3002:1: ( rule__FilterSpec__Group_15__1__Impl rule__FilterSpec__Group_15__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3003:2: rule__FilterSpec__Group_15__1__Impl rule__FilterSpec__Group_15__2
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_15__1__Impl_in_rule__FilterSpec__Group_15__16157);
            rule__FilterSpec__Group_15__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_15__2_in_rule__FilterSpec__Group_15__16160);
            rule__FilterSpec__Group_15__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__1"


    // $ANTLR start "rule__FilterSpec__Group_15__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3010:1: rule__FilterSpec__Group_15__1__Impl : ( ( rule__FilterSpec__StatesAssignment_15_1 ) ) ;
    public final void rule__FilterSpec__Group_15__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3014:1: ( ( ( rule__FilterSpec__StatesAssignment_15_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3015:1: ( ( rule__FilterSpec__StatesAssignment_15_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3015:1: ( ( rule__FilterSpec__StatesAssignment_15_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3016:1: ( rule__FilterSpec__StatesAssignment_15_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getStatesAssignment_15_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3017:1: ( rule__FilterSpec__StatesAssignment_15_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3017:2: rule__FilterSpec__StatesAssignment_15_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__StatesAssignment_15_1_in_rule__FilterSpec__Group_15__1__Impl6187);
            rule__FilterSpec__StatesAssignment_15_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getStatesAssignment_15_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_15__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3027:1: rule__FilterSpec__Group_15__2 : rule__FilterSpec__Group_15__2__Impl ;
    public final void rule__FilterSpec__Group_15__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3031:1: ( rule__FilterSpec__Group_15__2__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3032:2: rule__FilterSpec__Group_15__2__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_15__2__Impl_in_rule__FilterSpec__Group_15__26217);
            rule__FilterSpec__Group_15__2__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__2"


    // $ANTLR start "rule__FilterSpec__Group_15__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3038:1: rule__FilterSpec__Group_15__2__Impl : ( ( rule__FilterSpec__Group_15_2__0 )* ) ;
    public final void rule__FilterSpec__Group_15__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3042:1: ( ( ( rule__FilterSpec__Group_15_2__0 )* ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3043:1: ( ( rule__FilterSpec__Group_15_2__0 )* )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3043:1: ( ( rule__FilterSpec__Group_15_2__0 )* )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3044:1: ( rule__FilterSpec__Group_15_2__0 )*
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_15_2()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3045:1: ( rule__FilterSpec__Group_15_2__0 )*
            loop26:
            do {
                int alt26=2;
                int LA26_0 = input.LA(1);

                if ( (LA26_0==46) ) {
                    alt26=1;
                }


                switch (alt26) {
            	case 1 :
            	    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3045:2: rule__FilterSpec__Group_15_2__0
            	    {
            	    pushFollow(FOLLOW_rule__FilterSpec__Group_15_2__0_in_rule__FilterSpec__Group_15__2__Impl6244);
            	    rule__FilterSpec__Group_15_2__0();

            	    state._fsp--;


            	    }
            	    break;

            	default :
            	    break loop26;
                }
            } while (true);

             after(grammarAccess.getFilterSpecAccess().getGroup_15_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15__2__Impl"


    // $ANTLR start "rule__FilterSpec__Group_15_2__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3061:1: rule__FilterSpec__Group_15_2__0 : rule__FilterSpec__Group_15_2__0__Impl rule__FilterSpec__Group_15_2__1 ;
    public final void rule__FilterSpec__Group_15_2__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3065:1: ( rule__FilterSpec__Group_15_2__0__Impl rule__FilterSpec__Group_15_2__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3066:2: rule__FilterSpec__Group_15_2__0__Impl rule__FilterSpec__Group_15_2__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_15_2__0__Impl_in_rule__FilterSpec__Group_15_2__06281);
            rule__FilterSpec__Group_15_2__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_15_2__1_in_rule__FilterSpec__Group_15_2__06284);
            rule__FilterSpec__Group_15_2__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15_2__0"


    // $ANTLR start "rule__FilterSpec__Group_15_2__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3073:1: rule__FilterSpec__Group_15_2__0__Impl : ( ',' ) ;
    public final void rule__FilterSpec__Group_15_2__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3077:1: ( ( ',' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3078:1: ( ',' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3078:1: ( ',' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3079:1: ','
            {
             before(grammarAccess.getFilterSpecAccess().getCommaKeyword_15_2_0()); 
            match(input,46,FOLLOW_46_in_rule__FilterSpec__Group_15_2__0__Impl6312); 
             after(grammarAccess.getFilterSpecAccess().getCommaKeyword_15_2_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15_2__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_15_2__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3092:1: rule__FilterSpec__Group_15_2__1 : rule__FilterSpec__Group_15_2__1__Impl ;
    public final void rule__FilterSpec__Group_15_2__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3096:1: ( rule__FilterSpec__Group_15_2__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3097:2: rule__FilterSpec__Group_15_2__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_15_2__1__Impl_in_rule__FilterSpec__Group_15_2__16343);
            rule__FilterSpec__Group_15_2__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15_2__1"


    // $ANTLR start "rule__FilterSpec__Group_15_2__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3103:1: rule__FilterSpec__Group_15_2__1__Impl : ( ( rule__FilterSpec__StatesAssignment_15_2_1 ) ) ;
    public final void rule__FilterSpec__Group_15_2__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3107:1: ( ( ( rule__FilterSpec__StatesAssignment_15_2_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3108:1: ( ( rule__FilterSpec__StatesAssignment_15_2_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3108:1: ( ( rule__FilterSpec__StatesAssignment_15_2_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3109:1: ( rule__FilterSpec__StatesAssignment_15_2_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getStatesAssignment_15_2_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3110:1: ( rule__FilterSpec__StatesAssignment_15_2_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3110:2: rule__FilterSpec__StatesAssignment_15_2_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__StatesAssignment_15_2_1_in_rule__FilterSpec__Group_15_2__1__Impl6370);
            rule__FilterSpec__StatesAssignment_15_2_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getStatesAssignment_15_2_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_15_2__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3124:1: rule__FilterSpec__Group_16__0 : rule__FilterSpec__Group_16__0__Impl rule__FilterSpec__Group_16__1 ;
    public final void rule__FilterSpec__Group_16__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3128:1: ( rule__FilterSpec__Group_16__0__Impl rule__FilterSpec__Group_16__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3129:2: rule__FilterSpec__Group_16__0__Impl rule__FilterSpec__Group_16__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16__0__Impl_in_rule__FilterSpec__Group_16__06404);
            rule__FilterSpec__Group_16__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16__1_in_rule__FilterSpec__Group_16__06407);
            rule__FilterSpec__Group_16__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__0"


    // $ANTLR start "rule__FilterSpec__Group_16__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3136:1: rule__FilterSpec__Group_16__0__Impl : ( '--tcp-flags' ) ;
    public final void rule__FilterSpec__Group_16__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3140:1: ( ( '--tcp-flags' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3141:1: ( '--tcp-flags' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3141:1: ( '--tcp-flags' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3142:1: '--tcp-flags'
            {
             before(grammarAccess.getFilterSpecAccess().getTcpFlagsKeyword_16_0()); 
            match(input,50,FOLLOW_50_in_rule__FilterSpec__Group_16__0__Impl6435); 
             after(grammarAccess.getFilterSpecAccess().getTcpFlagsKeyword_16_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3155:1: rule__FilterSpec__Group_16__1 : rule__FilterSpec__Group_16__1__Impl rule__FilterSpec__Group_16__2 ;
    public final void rule__FilterSpec__Group_16__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3159:1: ( rule__FilterSpec__Group_16__1__Impl rule__FilterSpec__Group_16__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3160:2: rule__FilterSpec__Group_16__1__Impl rule__FilterSpec__Group_16__2
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16__1__Impl_in_rule__FilterSpec__Group_16__16466);
            rule__FilterSpec__Group_16__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16__2_in_rule__FilterSpec__Group_16__16469);
            rule__FilterSpec__Group_16__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__1"


    // $ANTLR start "rule__FilterSpec__Group_16__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3167:1: rule__FilterSpec__Group_16__1__Impl : ( ( rule__FilterSpec__ExamFlagsAssignment_16_1 ) ) ;
    public final void rule__FilterSpec__Group_16__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3171:1: ( ( ( rule__FilterSpec__ExamFlagsAssignment_16_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3172:1: ( ( rule__FilterSpec__ExamFlagsAssignment_16_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3172:1: ( ( rule__FilterSpec__ExamFlagsAssignment_16_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3173:1: ( rule__FilterSpec__ExamFlagsAssignment_16_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getExamFlagsAssignment_16_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3174:1: ( rule__FilterSpec__ExamFlagsAssignment_16_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3174:2: rule__FilterSpec__ExamFlagsAssignment_16_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__ExamFlagsAssignment_16_1_in_rule__FilterSpec__Group_16__1__Impl6496);
            rule__FilterSpec__ExamFlagsAssignment_16_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getExamFlagsAssignment_16_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3184:1: rule__FilterSpec__Group_16__2 : rule__FilterSpec__Group_16__2__Impl rule__FilterSpec__Group_16__3 ;
    public final void rule__FilterSpec__Group_16__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3188:1: ( rule__FilterSpec__Group_16__2__Impl rule__FilterSpec__Group_16__3 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3189:2: rule__FilterSpec__Group_16__2__Impl rule__FilterSpec__Group_16__3
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16__2__Impl_in_rule__FilterSpec__Group_16__26526);
            rule__FilterSpec__Group_16__2__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16__3_in_rule__FilterSpec__Group_16__26529);
            rule__FilterSpec__Group_16__3();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__2"


    // $ANTLR start "rule__FilterSpec__Group_16__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3196:1: rule__FilterSpec__Group_16__2__Impl : ( ( rule__FilterSpec__Group_16_2__0 )* ) ;
    public final void rule__FilterSpec__Group_16__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3200:1: ( ( ( rule__FilterSpec__Group_16_2__0 )* ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3201:1: ( ( rule__FilterSpec__Group_16_2__0 )* )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3201:1: ( ( rule__FilterSpec__Group_16_2__0 )* )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3202:1: ( rule__FilterSpec__Group_16_2__0 )*
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_16_2()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3203:1: ( rule__FilterSpec__Group_16_2__0 )*
            loop27:
            do {
                int alt27=2;
                int LA27_0 = input.LA(1);

                if ( (LA27_0==46) ) {
                    alt27=1;
                }


                switch (alt27) {
            	case 1 :
            	    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3203:2: rule__FilterSpec__Group_16_2__0
            	    {
            	    pushFollow(FOLLOW_rule__FilterSpec__Group_16_2__0_in_rule__FilterSpec__Group_16__2__Impl6556);
            	    rule__FilterSpec__Group_16_2__0();

            	    state._fsp--;


            	    }
            	    break;

            	default :
            	    break loop27;
                }
            } while (true);

             after(grammarAccess.getFilterSpecAccess().getGroup_16_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__2__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16__3"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3213:1: rule__FilterSpec__Group_16__3 : rule__FilterSpec__Group_16__3__Impl rule__FilterSpec__Group_16__4 ;
    public final void rule__FilterSpec__Group_16__3() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3217:1: ( rule__FilterSpec__Group_16__3__Impl rule__FilterSpec__Group_16__4 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3218:2: rule__FilterSpec__Group_16__3__Impl rule__FilterSpec__Group_16__4
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16__3__Impl_in_rule__FilterSpec__Group_16__36587);
            rule__FilterSpec__Group_16__3__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16__4_in_rule__FilterSpec__Group_16__36590);
            rule__FilterSpec__Group_16__4();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__3"


    // $ANTLR start "rule__FilterSpec__Group_16__3__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3225:1: rule__FilterSpec__Group_16__3__Impl : ( ( rule__FilterSpec__FlagsAssignment_16_3 ) ) ;
    public final void rule__FilterSpec__Group_16__3__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3229:1: ( ( ( rule__FilterSpec__FlagsAssignment_16_3 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3230:1: ( ( rule__FilterSpec__FlagsAssignment_16_3 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3230:1: ( ( rule__FilterSpec__FlagsAssignment_16_3 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3231:1: ( rule__FilterSpec__FlagsAssignment_16_3 )
            {
             before(grammarAccess.getFilterSpecAccess().getFlagsAssignment_16_3()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3232:1: ( rule__FilterSpec__FlagsAssignment_16_3 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3232:2: rule__FilterSpec__FlagsAssignment_16_3
            {
            pushFollow(FOLLOW_rule__FilterSpec__FlagsAssignment_16_3_in_rule__FilterSpec__Group_16__3__Impl6617);
            rule__FilterSpec__FlagsAssignment_16_3();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getFlagsAssignment_16_3()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__3__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16__4"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3242:1: rule__FilterSpec__Group_16__4 : rule__FilterSpec__Group_16__4__Impl ;
    public final void rule__FilterSpec__Group_16__4() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3246:1: ( rule__FilterSpec__Group_16__4__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3247:2: rule__FilterSpec__Group_16__4__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16__4__Impl_in_rule__FilterSpec__Group_16__46647);
            rule__FilterSpec__Group_16__4__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__4"


    // $ANTLR start "rule__FilterSpec__Group_16__4__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3253:1: rule__FilterSpec__Group_16__4__Impl : ( ( rule__FilterSpec__Group_16_4__0 )* ) ;
    public final void rule__FilterSpec__Group_16__4__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3257:1: ( ( ( rule__FilterSpec__Group_16_4__0 )* ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3258:1: ( ( rule__FilterSpec__Group_16_4__0 )* )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3258:1: ( ( rule__FilterSpec__Group_16_4__0 )* )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3259:1: ( rule__FilterSpec__Group_16_4__0 )*
            {
             before(grammarAccess.getFilterSpecAccess().getGroup_16_4()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3260:1: ( rule__FilterSpec__Group_16_4__0 )*
            loop28:
            do {
                int alt28=2;
                int LA28_0 = input.LA(1);

                if ( (LA28_0==46) ) {
                    alt28=1;
                }


                switch (alt28) {
            	case 1 :
            	    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3260:2: rule__FilterSpec__Group_16_4__0
            	    {
            	    pushFollow(FOLLOW_rule__FilterSpec__Group_16_4__0_in_rule__FilterSpec__Group_16__4__Impl6674);
            	    rule__FilterSpec__Group_16_4__0();

            	    state._fsp--;


            	    }
            	    break;

            	default :
            	    break loop28;
                }
            } while (true);

             after(grammarAccess.getFilterSpecAccess().getGroup_16_4()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16__4__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16_2__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3280:1: rule__FilterSpec__Group_16_2__0 : rule__FilterSpec__Group_16_2__0__Impl rule__FilterSpec__Group_16_2__1 ;
    public final void rule__FilterSpec__Group_16_2__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3284:1: ( rule__FilterSpec__Group_16_2__0__Impl rule__FilterSpec__Group_16_2__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3285:2: rule__FilterSpec__Group_16_2__0__Impl rule__FilterSpec__Group_16_2__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16_2__0__Impl_in_rule__FilterSpec__Group_16_2__06715);
            rule__FilterSpec__Group_16_2__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16_2__1_in_rule__FilterSpec__Group_16_2__06718);
            rule__FilterSpec__Group_16_2__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_2__0"


    // $ANTLR start "rule__FilterSpec__Group_16_2__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3292:1: rule__FilterSpec__Group_16_2__0__Impl : ( ',' ) ;
    public final void rule__FilterSpec__Group_16_2__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3296:1: ( ( ',' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3297:1: ( ',' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3297:1: ( ',' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3298:1: ','
            {
             before(grammarAccess.getFilterSpecAccess().getCommaKeyword_16_2_0()); 
            match(input,46,FOLLOW_46_in_rule__FilterSpec__Group_16_2__0__Impl6746); 
             after(grammarAccess.getFilterSpecAccess().getCommaKeyword_16_2_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_2__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16_2__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3311:1: rule__FilterSpec__Group_16_2__1 : rule__FilterSpec__Group_16_2__1__Impl ;
    public final void rule__FilterSpec__Group_16_2__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3315:1: ( rule__FilterSpec__Group_16_2__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3316:2: rule__FilterSpec__Group_16_2__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16_2__1__Impl_in_rule__FilterSpec__Group_16_2__16777);
            rule__FilterSpec__Group_16_2__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_2__1"


    // $ANTLR start "rule__FilterSpec__Group_16_2__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3322:1: rule__FilterSpec__Group_16_2__1__Impl : ( ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 ) ) ;
    public final void rule__FilterSpec__Group_16_2__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3326:1: ( ( ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3327:1: ( ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3327:1: ( ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3328:1: ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getExamFlagsAssignment_16_2_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3329:1: ( rule__FilterSpec__ExamFlagsAssignment_16_2_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3329:2: rule__FilterSpec__ExamFlagsAssignment_16_2_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__ExamFlagsAssignment_16_2_1_in_rule__FilterSpec__Group_16_2__1__Impl6804);
            rule__FilterSpec__ExamFlagsAssignment_16_2_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getExamFlagsAssignment_16_2_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_2__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16_4__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3343:1: rule__FilterSpec__Group_16_4__0 : rule__FilterSpec__Group_16_4__0__Impl rule__FilterSpec__Group_16_4__1 ;
    public final void rule__FilterSpec__Group_16_4__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3347:1: ( rule__FilterSpec__Group_16_4__0__Impl rule__FilterSpec__Group_16_4__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3348:2: rule__FilterSpec__Group_16_4__0__Impl rule__FilterSpec__Group_16_4__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16_4__0__Impl_in_rule__FilterSpec__Group_16_4__06838);
            rule__FilterSpec__Group_16_4__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_16_4__1_in_rule__FilterSpec__Group_16_4__06841);
            rule__FilterSpec__Group_16_4__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_4__0"


    // $ANTLR start "rule__FilterSpec__Group_16_4__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3355:1: rule__FilterSpec__Group_16_4__0__Impl : ( ',' ) ;
    public final void rule__FilterSpec__Group_16_4__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3359:1: ( ( ',' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3360:1: ( ',' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3360:1: ( ',' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3361:1: ','
            {
             before(grammarAccess.getFilterSpecAccess().getCommaKeyword_16_4_0()); 
            match(input,46,FOLLOW_46_in_rule__FilterSpec__Group_16_4__0__Impl6869); 
             after(grammarAccess.getFilterSpecAccess().getCommaKeyword_16_4_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_4__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_16_4__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3374:1: rule__FilterSpec__Group_16_4__1 : rule__FilterSpec__Group_16_4__1__Impl ;
    public final void rule__FilterSpec__Group_16_4__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3378:1: ( rule__FilterSpec__Group_16_4__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3379:2: rule__FilterSpec__Group_16_4__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_16_4__1__Impl_in_rule__FilterSpec__Group_16_4__16900);
            rule__FilterSpec__Group_16_4__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_4__1"


    // $ANTLR start "rule__FilterSpec__Group_16_4__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3385:1: rule__FilterSpec__Group_16_4__1__Impl : ( ( rule__FilterSpec__FlagsAssignment_16_4_1 ) ) ;
    public final void rule__FilterSpec__Group_16_4__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3389:1: ( ( ( rule__FilterSpec__FlagsAssignment_16_4_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3390:1: ( ( rule__FilterSpec__FlagsAssignment_16_4_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3390:1: ( ( rule__FilterSpec__FlagsAssignment_16_4_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3391:1: ( rule__FilterSpec__FlagsAssignment_16_4_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getFlagsAssignment_16_4_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3392:1: ( rule__FilterSpec__FlagsAssignment_16_4_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3392:2: rule__FilterSpec__FlagsAssignment_16_4_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__FlagsAssignment_16_4_1_in_rule__FilterSpec__Group_16_4__1__Impl6927);
            rule__FilterSpec__FlagsAssignment_16_4_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getFlagsAssignment_16_4_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_16_4__1__Impl"


    // $ANTLR start "rule__FilterSpec__Group_19__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3406:1: rule__FilterSpec__Group_19__0 : rule__FilterSpec__Group_19__0__Impl rule__FilterSpec__Group_19__1 ;
    public final void rule__FilterSpec__Group_19__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3410:1: ( rule__FilterSpec__Group_19__0__Impl rule__FilterSpec__Group_19__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3411:2: rule__FilterSpec__Group_19__0__Impl rule__FilterSpec__Group_19__1
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_19__0__Impl_in_rule__FilterSpec__Group_19__06961);
            rule__FilterSpec__Group_19__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__FilterSpec__Group_19__1_in_rule__FilterSpec__Group_19__06964);
            rule__FilterSpec__Group_19__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_19__0"


    // $ANTLR start "rule__FilterSpec__Group_19__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3418:1: rule__FilterSpec__Group_19__0__Impl : ( '--log-prefix' ) ;
    public final void rule__FilterSpec__Group_19__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3422:1: ( ( '--log-prefix' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3423:1: ( '--log-prefix' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3423:1: ( '--log-prefix' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3424:1: '--log-prefix'
            {
             before(grammarAccess.getFilterSpecAccess().getLogPrefixKeyword_19_0()); 
            match(input,51,FOLLOW_51_in_rule__FilterSpec__Group_19__0__Impl6992); 
             after(grammarAccess.getFilterSpecAccess().getLogPrefixKeyword_19_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_19__0__Impl"


    // $ANTLR start "rule__FilterSpec__Group_19__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3437:1: rule__FilterSpec__Group_19__1 : rule__FilterSpec__Group_19__1__Impl ;
    public final void rule__FilterSpec__Group_19__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3441:1: ( rule__FilterSpec__Group_19__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3442:2: rule__FilterSpec__Group_19__1__Impl
            {
            pushFollow(FOLLOW_rule__FilterSpec__Group_19__1__Impl_in_rule__FilterSpec__Group_19__17023);
            rule__FilterSpec__Group_19__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_19__1"


    // $ANTLR start "rule__FilterSpec__Group_19__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3448:1: rule__FilterSpec__Group_19__1__Impl : ( ( rule__FilterSpec__LpAssignment_19_1 ) ) ;
    public final void rule__FilterSpec__Group_19__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3452:1: ( ( ( rule__FilterSpec__LpAssignment_19_1 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3453:1: ( ( rule__FilterSpec__LpAssignment_19_1 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3453:1: ( ( rule__FilterSpec__LpAssignment_19_1 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3454:1: ( rule__FilterSpec__LpAssignment_19_1 )
            {
             before(grammarAccess.getFilterSpecAccess().getLpAssignment_19_1()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3455:1: ( rule__FilterSpec__LpAssignment_19_1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3455:2: rule__FilterSpec__LpAssignment_19_1
            {
            pushFollow(FOLLOW_rule__FilterSpec__LpAssignment_19_1_in_rule__FilterSpec__Group_19__1__Impl7050);
            rule__FilterSpec__LpAssignment_19_1();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getLpAssignment_19_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__Group_19__1__Impl"


    // $ANTLR start "rule__ChainDeclaration__Group__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3469:1: rule__ChainDeclaration__Group__0 : rule__ChainDeclaration__Group__0__Impl rule__ChainDeclaration__Group__1 ;
    public final void rule__ChainDeclaration__Group__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3473:1: ( rule__ChainDeclaration__Group__0__Impl rule__ChainDeclaration__Group__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3474:2: rule__ChainDeclaration__Group__0__Impl rule__ChainDeclaration__Group__1
            {
            pushFollow(FOLLOW_rule__ChainDeclaration__Group__0__Impl_in_rule__ChainDeclaration__Group__07084);
            rule__ChainDeclaration__Group__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__ChainDeclaration__Group__1_in_rule__ChainDeclaration__Group__07087);
            rule__ChainDeclaration__Group__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__0"


    // $ANTLR start "rule__ChainDeclaration__Group__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3481:1: rule__ChainDeclaration__Group__0__Impl : ( 'iptables' ) ;
    public final void rule__ChainDeclaration__Group__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3485:1: ( ( 'iptables' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3486:1: ( 'iptables' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3486:1: ( 'iptables' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3487:1: 'iptables'
            {
             before(grammarAccess.getChainDeclarationAccess().getIptablesKeyword_0()); 
            match(input,36,FOLLOW_36_in_rule__ChainDeclaration__Group__0__Impl7115); 
             after(grammarAccess.getChainDeclarationAccess().getIptablesKeyword_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__0__Impl"


    // $ANTLR start "rule__ChainDeclaration__Group__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3500:1: rule__ChainDeclaration__Group__1 : rule__ChainDeclaration__Group__1__Impl rule__ChainDeclaration__Group__2 ;
    public final void rule__ChainDeclaration__Group__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3504:1: ( rule__ChainDeclaration__Group__1__Impl rule__ChainDeclaration__Group__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3505:2: rule__ChainDeclaration__Group__1__Impl rule__ChainDeclaration__Group__2
            {
            pushFollow(FOLLOW_rule__ChainDeclaration__Group__1__Impl_in_rule__ChainDeclaration__Group__17146);
            rule__ChainDeclaration__Group__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__ChainDeclaration__Group__2_in_rule__ChainDeclaration__Group__17149);
            rule__ChainDeclaration__Group__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__1"


    // $ANTLR start "rule__ChainDeclaration__Group__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3512:1: rule__ChainDeclaration__Group__1__Impl : ( '-N' ) ;
    public final void rule__ChainDeclaration__Group__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3516:1: ( ( '-N' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3517:1: ( '-N' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3517:1: ( '-N' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3518:1: '-N'
            {
             before(grammarAccess.getChainDeclarationAccess().getNKeyword_1()); 
            match(input,52,FOLLOW_52_in_rule__ChainDeclaration__Group__1__Impl7177); 
             after(grammarAccess.getChainDeclarationAccess().getNKeyword_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__1__Impl"


    // $ANTLR start "rule__ChainDeclaration__Group__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3531:1: rule__ChainDeclaration__Group__2 : rule__ChainDeclaration__Group__2__Impl ;
    public final void rule__ChainDeclaration__Group__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3535:1: ( rule__ChainDeclaration__Group__2__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3536:2: rule__ChainDeclaration__Group__2__Impl
            {
            pushFollow(FOLLOW_rule__ChainDeclaration__Group__2__Impl_in_rule__ChainDeclaration__Group__27208);
            rule__ChainDeclaration__Group__2__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__2"


    // $ANTLR start "rule__ChainDeclaration__Group__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3542:1: rule__ChainDeclaration__Group__2__Impl : ( ruleChainName ) ;
    public final void rule__ChainDeclaration__Group__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3546:1: ( ( ruleChainName ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3547:1: ( ruleChainName )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3547:1: ( ruleChainName )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3548:1: ruleChainName
            {
             before(grammarAccess.getChainDeclarationAccess().getChainNameParserRuleCall_2()); 
            pushFollow(FOLLOW_ruleChainName_in_rule__ChainDeclaration__Group__2__Impl7235);
            ruleChainName();

            state._fsp--;

             after(grammarAccess.getChainDeclarationAccess().getChainNameParserRuleCall_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainDeclaration__Group__2__Impl"


    // $ANTLR start "rule__IPExpr__Group__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3565:1: rule__IPExpr__Group__0 : rule__IPExpr__Group__0__Impl rule__IPExpr__Group__1 ;
    public final void rule__IPExpr__Group__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3569:1: ( rule__IPExpr__Group__0__Impl rule__IPExpr__Group__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3570:2: rule__IPExpr__Group__0__Impl rule__IPExpr__Group__1
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__0__Impl_in_rule__IPExpr__Group__07270);
            rule__IPExpr__Group__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__1_in_rule__IPExpr__Group__07273);
            rule__IPExpr__Group__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__0"


    // $ANTLR start "rule__IPExpr__Group__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3577:1: rule__IPExpr__Group__0__Impl : ( ruleipByteExpr ) ;
    public final void rule__IPExpr__Group__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3581:1: ( ( ruleipByteExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3582:1: ( ruleipByteExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3582:1: ( ruleipByteExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3583:1: ruleipByteExpr
            {
             before(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_0()); 
            pushFollow(FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__0__Impl7300);
            ruleipByteExpr();

            state._fsp--;

             after(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__0__Impl"


    // $ANTLR start "rule__IPExpr__Group__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3594:1: rule__IPExpr__Group__1 : rule__IPExpr__Group__1__Impl rule__IPExpr__Group__2 ;
    public final void rule__IPExpr__Group__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3598:1: ( rule__IPExpr__Group__1__Impl rule__IPExpr__Group__2 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3599:2: rule__IPExpr__Group__1__Impl rule__IPExpr__Group__2
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__1__Impl_in_rule__IPExpr__Group__17329);
            rule__IPExpr__Group__1__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__2_in_rule__IPExpr__Group__17332);
            rule__IPExpr__Group__2();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__1"


    // $ANTLR start "rule__IPExpr__Group__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3606:1: rule__IPExpr__Group__1__Impl : ( '.' ) ;
    public final void rule__IPExpr__Group__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3610:1: ( ( '.' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3611:1: ( '.' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3611:1: ( '.' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3612:1: '.'
            {
             before(grammarAccess.getIPExprAccess().getFullStopKeyword_1()); 
            match(input,53,FOLLOW_53_in_rule__IPExpr__Group__1__Impl7360); 
             after(grammarAccess.getIPExprAccess().getFullStopKeyword_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__1__Impl"


    // $ANTLR start "rule__IPExpr__Group__2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3625:1: rule__IPExpr__Group__2 : rule__IPExpr__Group__2__Impl rule__IPExpr__Group__3 ;
    public final void rule__IPExpr__Group__2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3629:1: ( rule__IPExpr__Group__2__Impl rule__IPExpr__Group__3 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3630:2: rule__IPExpr__Group__2__Impl rule__IPExpr__Group__3
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__2__Impl_in_rule__IPExpr__Group__27391);
            rule__IPExpr__Group__2__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__3_in_rule__IPExpr__Group__27394);
            rule__IPExpr__Group__3();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__2"


    // $ANTLR start "rule__IPExpr__Group__2__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3637:1: rule__IPExpr__Group__2__Impl : ( ruleipByteExpr ) ;
    public final void rule__IPExpr__Group__2__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3641:1: ( ( ruleipByteExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3642:1: ( ruleipByteExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3642:1: ( ruleipByteExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3643:1: ruleipByteExpr
            {
             before(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_2()); 
            pushFollow(FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__2__Impl7421);
            ruleipByteExpr();

            state._fsp--;

             after(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_2()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__2__Impl"


    // $ANTLR start "rule__IPExpr__Group__3"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3654:1: rule__IPExpr__Group__3 : rule__IPExpr__Group__3__Impl rule__IPExpr__Group__4 ;
    public final void rule__IPExpr__Group__3() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3658:1: ( rule__IPExpr__Group__3__Impl rule__IPExpr__Group__4 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3659:2: rule__IPExpr__Group__3__Impl rule__IPExpr__Group__4
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__3__Impl_in_rule__IPExpr__Group__37450);
            rule__IPExpr__Group__3__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__4_in_rule__IPExpr__Group__37453);
            rule__IPExpr__Group__4();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__3"


    // $ANTLR start "rule__IPExpr__Group__3__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3666:1: rule__IPExpr__Group__3__Impl : ( '.' ) ;
    public final void rule__IPExpr__Group__3__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3670:1: ( ( '.' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3671:1: ( '.' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3671:1: ( '.' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3672:1: '.'
            {
             before(grammarAccess.getIPExprAccess().getFullStopKeyword_3()); 
            match(input,53,FOLLOW_53_in_rule__IPExpr__Group__3__Impl7481); 
             after(grammarAccess.getIPExprAccess().getFullStopKeyword_3()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__3__Impl"


    // $ANTLR start "rule__IPExpr__Group__4"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3685:1: rule__IPExpr__Group__4 : rule__IPExpr__Group__4__Impl rule__IPExpr__Group__5 ;
    public final void rule__IPExpr__Group__4() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3689:1: ( rule__IPExpr__Group__4__Impl rule__IPExpr__Group__5 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3690:2: rule__IPExpr__Group__4__Impl rule__IPExpr__Group__5
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__4__Impl_in_rule__IPExpr__Group__47512);
            rule__IPExpr__Group__4__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__5_in_rule__IPExpr__Group__47515);
            rule__IPExpr__Group__5();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__4"


    // $ANTLR start "rule__IPExpr__Group__4__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3697:1: rule__IPExpr__Group__4__Impl : ( ruleipByteExpr ) ;
    public final void rule__IPExpr__Group__4__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3701:1: ( ( ruleipByteExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3702:1: ( ruleipByteExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3702:1: ( ruleipByteExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3703:1: ruleipByteExpr
            {
             before(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_4()); 
            pushFollow(FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__4__Impl7542);
            ruleipByteExpr();

            state._fsp--;

             after(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_4()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__4__Impl"


    // $ANTLR start "rule__IPExpr__Group__5"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3714:1: rule__IPExpr__Group__5 : rule__IPExpr__Group__5__Impl rule__IPExpr__Group__6 ;
    public final void rule__IPExpr__Group__5() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3718:1: ( rule__IPExpr__Group__5__Impl rule__IPExpr__Group__6 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3719:2: rule__IPExpr__Group__5__Impl rule__IPExpr__Group__6
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__5__Impl_in_rule__IPExpr__Group__57571);
            rule__IPExpr__Group__5__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__6_in_rule__IPExpr__Group__57574);
            rule__IPExpr__Group__6();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__5"


    // $ANTLR start "rule__IPExpr__Group__5__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3726:1: rule__IPExpr__Group__5__Impl : ( '.' ) ;
    public final void rule__IPExpr__Group__5__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3730:1: ( ( '.' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3731:1: ( '.' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3731:1: ( '.' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3732:1: '.'
            {
             before(grammarAccess.getIPExprAccess().getFullStopKeyword_5()); 
            match(input,53,FOLLOW_53_in_rule__IPExpr__Group__5__Impl7602); 
             after(grammarAccess.getIPExprAccess().getFullStopKeyword_5()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__5__Impl"


    // $ANTLR start "rule__IPExpr__Group__6"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3745:1: rule__IPExpr__Group__6 : rule__IPExpr__Group__6__Impl rule__IPExpr__Group__7 ;
    public final void rule__IPExpr__Group__6() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3749:1: ( rule__IPExpr__Group__6__Impl rule__IPExpr__Group__7 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3750:2: rule__IPExpr__Group__6__Impl rule__IPExpr__Group__7
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__6__Impl_in_rule__IPExpr__Group__67633);
            rule__IPExpr__Group__6__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IPExpr__Group__7_in_rule__IPExpr__Group__67636);
            rule__IPExpr__Group__7();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__6"


    // $ANTLR start "rule__IPExpr__Group__6__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3757:1: rule__IPExpr__Group__6__Impl : ( ruleipByteExpr ) ;
    public final void rule__IPExpr__Group__6__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3761:1: ( ( ruleipByteExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3762:1: ( ruleipByteExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3762:1: ( ruleipByteExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3763:1: ruleipByteExpr
            {
             before(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_6()); 
            pushFollow(FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__6__Impl7663);
            ruleipByteExpr();

            state._fsp--;

             after(grammarAccess.getIPExprAccess().getIpByteExprParserRuleCall_6()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__6__Impl"


    // $ANTLR start "rule__IPExpr__Group__7"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3774:1: rule__IPExpr__Group__7 : rule__IPExpr__Group__7__Impl ;
    public final void rule__IPExpr__Group__7() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3778:1: ( rule__IPExpr__Group__7__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3779:2: rule__IPExpr__Group__7__Impl
            {
            pushFollow(FOLLOW_rule__IPExpr__Group__7__Impl_in_rule__IPExpr__Group__77692);
            rule__IPExpr__Group__7__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__7"


    // $ANTLR start "rule__IPExpr__Group__7__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3785:1: rule__IPExpr__Group__7__Impl : ( ( ruleIpRangeExpr )? ) ;
    public final void rule__IPExpr__Group__7__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3789:1: ( ( ( ruleIpRangeExpr )? ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3790:1: ( ( ruleIpRangeExpr )? )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3790:1: ( ( ruleIpRangeExpr )? )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3791:1: ( ruleIpRangeExpr )?
            {
             before(grammarAccess.getIPExprAccess().getIpRangeExprParserRuleCall_7()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3792:1: ( ruleIpRangeExpr )?
            int alt29=2;
            int LA29_0 = input.LA(1);

            if ( (LA29_0==54) ) {
                alt29=1;
            }
            switch (alt29) {
                case 1 :
                    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3792:3: ruleIpRangeExpr
                    {
                    pushFollow(FOLLOW_ruleIpRangeExpr_in_rule__IPExpr__Group__7__Impl7720);
                    ruleIpRangeExpr();

                    state._fsp--;


                    }
                    break;

            }

             after(grammarAccess.getIPExprAccess().getIpRangeExprParserRuleCall_7()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IPExpr__Group__7__Impl"


    // $ANTLR start "rule__IpRangeExpr__Group__0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3818:1: rule__IpRangeExpr__Group__0 : rule__IpRangeExpr__Group__0__Impl rule__IpRangeExpr__Group__1 ;
    public final void rule__IpRangeExpr__Group__0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3822:1: ( rule__IpRangeExpr__Group__0__Impl rule__IpRangeExpr__Group__1 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3823:2: rule__IpRangeExpr__Group__0__Impl rule__IpRangeExpr__Group__1
            {
            pushFollow(FOLLOW_rule__IpRangeExpr__Group__0__Impl_in_rule__IpRangeExpr__Group__07767);
            rule__IpRangeExpr__Group__0__Impl();

            state._fsp--;

            pushFollow(FOLLOW_rule__IpRangeExpr__Group__1_in_rule__IpRangeExpr__Group__07770);
            rule__IpRangeExpr__Group__1();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IpRangeExpr__Group__0"


    // $ANTLR start "rule__IpRangeExpr__Group__0__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3830:1: rule__IpRangeExpr__Group__0__Impl : ( '/' ) ;
    public final void rule__IpRangeExpr__Group__0__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3834:1: ( ( '/' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3835:1: ( '/' )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3835:1: ( '/' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3836:1: '/'
            {
             before(grammarAccess.getIpRangeExprAccess().getSolidusKeyword_0()); 
            match(input,54,FOLLOW_54_in_rule__IpRangeExpr__Group__0__Impl7798); 
             after(grammarAccess.getIpRangeExprAccess().getSolidusKeyword_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IpRangeExpr__Group__0__Impl"


    // $ANTLR start "rule__IpRangeExpr__Group__1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3849:1: rule__IpRangeExpr__Group__1 : rule__IpRangeExpr__Group__1__Impl ;
    public final void rule__IpRangeExpr__Group__1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3853:1: ( rule__IpRangeExpr__Group__1__Impl )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3854:2: rule__IpRangeExpr__Group__1__Impl
            {
            pushFollow(FOLLOW_rule__IpRangeExpr__Group__1__Impl_in_rule__IpRangeExpr__Group__17829);
            rule__IpRangeExpr__Group__1__Impl();

            state._fsp--;


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IpRangeExpr__Group__1"


    // $ANTLR start "rule__IpRangeExpr__Group__1__Impl"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3860:1: rule__IpRangeExpr__Group__1__Impl : ( RULE_INT ) ;
    public final void rule__IpRangeExpr__Group__1__Impl() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3864:1: ( ( RULE_INT ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3865:1: ( RULE_INT )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3865:1: ( RULE_INT )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3866:1: RULE_INT
            {
             before(grammarAccess.getIpRangeExprAccess().getINTTerminalRuleCall_1()); 
            match(input,RULE_INT,FOLLOW_RULE_INT_in_rule__IpRangeExpr__Group__1__Impl7856); 
             after(grammarAccess.getIpRangeExprAccess().getINTTerminalRuleCall_1()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__IpRangeExpr__Group__1__Impl"


    // $ANTLR start "rule__Model__RulesAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3882:1: rule__Model__RulesAssignment : ( ruleRule ) ;
    public final void rule__Model__RulesAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3886:1: ( ( ruleRule ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3887:1: ( ruleRule )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3887:1: ( ruleRule )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3888:1: ruleRule
            {
             before(grammarAccess.getModelAccess().getRulesRuleParserRuleCall_0()); 
            pushFollow(FOLLOW_ruleRule_in_rule__Model__RulesAssignment7894);
            ruleRule();

            state._fsp--;

             after(grammarAccess.getModelAccess().getRulesRuleParserRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Model__RulesAssignment"


    // $ANTLR start "rule__Rule__DeclarationAssignment_0"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3897:1: rule__Rule__DeclarationAssignment_0 : ( ruleChainDeclaration ) ;
    public final void rule__Rule__DeclarationAssignment_0() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3901:1: ( ( ruleChainDeclaration ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3902:1: ( ruleChainDeclaration )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3902:1: ( ruleChainDeclaration )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3903:1: ruleChainDeclaration
            {
             before(grammarAccess.getRuleAccess().getDeclarationChainDeclarationParserRuleCall_0_0()); 
            pushFollow(FOLLOW_ruleChainDeclaration_in_rule__Rule__DeclarationAssignment_07925);
            ruleChainDeclaration();

            state._fsp--;

             after(grammarAccess.getRuleAccess().getDeclarationChainDeclarationParserRuleCall_0_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Rule__DeclarationAssignment_0"


    // $ANTLR start "rule__Rule__FilterAssignment_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3912:1: rule__Rule__FilterAssignment_1 : ( ruleFilterDeclaration ) ;
    public final void rule__Rule__FilterAssignment_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3916:1: ( ( ruleFilterDeclaration ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3917:1: ( ruleFilterDeclaration )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3917:1: ( ruleFilterDeclaration )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3918:1: ruleFilterDeclaration
            {
             before(grammarAccess.getRuleAccess().getFilterFilterDeclarationParserRuleCall_1_0()); 
            pushFollow(FOLLOW_ruleFilterDeclaration_in_rule__Rule__FilterAssignment_17956);
            ruleFilterDeclaration();

            state._fsp--;

             after(grammarAccess.getRuleAccess().getFilterFilterDeclarationParserRuleCall_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Rule__FilterAssignment_1"


    // $ANTLR start "rule__FilterDeclaration__FilterAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3927:1: rule__FilterDeclaration__FilterAssignment : ( ruleFilteringSpec ) ;
    public final void rule__FilterDeclaration__FilterAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3931:1: ( ( ruleFilteringSpec ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3932:1: ( ruleFilteringSpec )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3932:1: ( ruleFilteringSpec )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3933:1: ruleFilteringSpec
            {
             before(grammarAccess.getFilterDeclarationAccess().getFilterFilteringSpecParserRuleCall_0()); 
            pushFollow(FOLLOW_ruleFilteringSpec_in_rule__FilterDeclaration__FilterAssignment7987);
            ruleFilteringSpec();

            state._fsp--;

             after(grammarAccess.getFilterDeclarationAccess().getFilterFilteringSpecParserRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterDeclaration__FilterAssignment"


    // $ANTLR start "rule__FilterSpec__OptionAssignment_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3942:1: rule__FilterSpec__OptionAssignment_1 : ( ( rule__FilterSpec__OptionAlternatives_1_0 ) ) ;
    public final void rule__FilterSpec__OptionAssignment_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3946:1: ( ( ( rule__FilterSpec__OptionAlternatives_1_0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3947:1: ( ( rule__FilterSpec__OptionAlternatives_1_0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3947:1: ( ( rule__FilterSpec__OptionAlternatives_1_0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3948:1: ( rule__FilterSpec__OptionAlternatives_1_0 )
            {
             before(grammarAccess.getFilterSpecAccess().getOptionAlternatives_1_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3949:1: ( rule__FilterSpec__OptionAlternatives_1_0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3949:2: rule__FilterSpec__OptionAlternatives_1_0
            {
            pushFollow(FOLLOW_rule__FilterSpec__OptionAlternatives_1_0_in_rule__FilterSpec__OptionAssignment_18018);
            rule__FilterSpec__OptionAlternatives_1_0();

            state._fsp--;


            }

             after(grammarAccess.getFilterSpecAccess().getOptionAlternatives_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__OptionAssignment_1"


    // $ANTLR start "rule__FilterSpec__ChainAssignment_2"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3958:1: rule__FilterSpec__ChainAssignment_2 : ( ruleChain ) ;
    public final void rule__FilterSpec__ChainAssignment_2() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3962:1: ( ( ruleChain ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3963:1: ( ruleChain )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3963:1: ( ruleChain )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3964:1: ruleChain
            {
             before(grammarAccess.getFilterSpecAccess().getChainChainParserRuleCall_2_0()); 
            pushFollow(FOLLOW_ruleChain_in_rule__FilterSpec__ChainAssignment_28051);
            ruleChain();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getChainChainParserRuleCall_2_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__ChainAssignment_2"


    // $ANTLR start "rule__FilterSpec__ProtocolAssignment_3_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3973:1: rule__FilterSpec__ProtocolAssignment_3_1 : ( ruleProtocol ) ;
    public final void rule__FilterSpec__ProtocolAssignment_3_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3977:1: ( ( ruleProtocol ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3978:1: ( ruleProtocol )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3978:1: ( ruleProtocol )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3979:1: ruleProtocol
            {
             before(grammarAccess.getFilterSpecAccess().getProtocolProtocolParserRuleCall_3_1_0()); 
            pushFollow(FOLLOW_ruleProtocol_in_rule__FilterSpec__ProtocolAssignment_3_18082);
            ruleProtocol();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getProtocolProtocolParserRuleCall_3_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__ProtocolAssignment_3_1"


    // $ANTLR start "rule__FilterSpec__IpAssignment_4_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3988:1: rule__FilterSpec__IpAssignment_4_1 : ( ruleIPExpr ) ;
    public final void rule__FilterSpec__IpAssignment_4_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3992:1: ( ( ruleIPExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3993:1: ( ruleIPExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3993:1: ( ruleIPExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:3994:1: ruleIPExpr
            {
             before(grammarAccess.getFilterSpecAccess().getIpIPExprParserRuleCall_4_1_0()); 
            pushFollow(FOLLOW_ruleIPExpr_in_rule__FilterSpec__IpAssignment_4_18113);
            ruleIPExpr();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getIpIPExprParserRuleCall_4_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__IpAssignment_4_1"


    // $ANTLR start "rule__FilterSpec__InterfaceAssignment_5_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4003:1: rule__FilterSpec__InterfaceAssignment_5_1 : ( ruleInterface ) ;
    public final void rule__FilterSpec__InterfaceAssignment_5_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4007:1: ( ( ruleInterface ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4008:1: ( ruleInterface )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4008:1: ( ruleInterface )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4009:1: ruleInterface
            {
             before(grammarAccess.getFilterSpecAccess().getInterfaceInterfaceParserRuleCall_5_1_0()); 
            pushFollow(FOLLOW_ruleInterface_in_rule__FilterSpec__InterfaceAssignment_5_18144);
            ruleInterface();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getInterfaceInterfaceParserRuleCall_5_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__InterfaceAssignment_5_1"


    // $ANTLR start "rule__FilterSpec__IpDstAssignment_6_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4018:1: rule__FilterSpec__IpDstAssignment_6_1 : ( ruleIPExpr ) ;
    public final void rule__FilterSpec__IpDstAssignment_6_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4022:1: ( ( ruleIPExpr ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4023:1: ( ruleIPExpr )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4023:1: ( ruleIPExpr )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4024:1: ruleIPExpr
            {
             before(grammarAccess.getFilterSpecAccess().getIpDstIPExprParserRuleCall_6_1_0()); 
            pushFollow(FOLLOW_ruleIPExpr_in_rule__FilterSpec__IpDstAssignment_6_18175);
            ruleIPExpr();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getIpDstIPExprParserRuleCall_6_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__IpDstAssignment_6_1"


    // $ANTLR start "rule__FilterSpec__SourcePortAssignment_7_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4033:1: rule__FilterSpec__SourcePortAssignment_7_1 : ( RULE_INT ) ;
    public final void rule__FilterSpec__SourcePortAssignment_7_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4037:1: ( ( RULE_INT ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4038:1: ( RULE_INT )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4038:1: ( RULE_INT )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4039:1: RULE_INT
            {
             before(grammarAccess.getFilterSpecAccess().getSourcePortINTTerminalRuleCall_7_1_0()); 
            match(input,RULE_INT,FOLLOW_RULE_INT_in_rule__FilterSpec__SourcePortAssignment_7_18206); 
             after(grammarAccess.getFilterSpecAccess().getSourcePortINTTerminalRuleCall_7_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__SourcePortAssignment_7_1"


    // $ANTLR start "rule__FilterSpec__DestinationPortAssignment_8_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4048:1: rule__FilterSpec__DestinationPortAssignment_8_1 : ( RULE_INT ) ;
    public final void rule__FilterSpec__DestinationPortAssignment_8_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4052:1: ( ( RULE_INT ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4053:1: ( RULE_INT )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4053:1: ( RULE_INT )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4054:1: RULE_INT
            {
             before(grammarAccess.getFilterSpecAccess().getDestinationPortINTTerminalRuleCall_8_1_0()); 
            match(input,RULE_INT,FOLLOW_RULE_INT_in_rule__FilterSpec__DestinationPortAssignment_8_18237); 
             after(grammarAccess.getFilterSpecAccess().getDestinationPortINTTerminalRuleCall_8_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__DestinationPortAssignment_8_1"


    // $ANTLR start "rule__FilterSpec__NegAssignment_9"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4063:1: rule__FilterSpec__NegAssignment_9 : ( ( '!' ) ) ;
    public final void rule__FilterSpec__NegAssignment_9() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4067:1: ( ( ( '!' ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4068:1: ( ( '!' ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4068:1: ( ( '!' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4069:1: ( '!' )
            {
             before(grammarAccess.getFilterSpecAccess().getNegExclamationMarkKeyword_9_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4070:1: ( '!' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4071:1: '!'
            {
             before(grammarAccess.getFilterSpecAccess().getNegExclamationMarkKeyword_9_0()); 
            match(input,55,FOLLOW_55_in_rule__FilterSpec__NegAssignment_98273); 
             after(grammarAccess.getFilterSpecAccess().getNegExclamationMarkKeyword_9_0()); 

            }

             after(grammarAccess.getFilterSpecAccess().getNegExclamationMarkKeyword_9_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__NegAssignment_9"


    // $ANTLR start "rule__FilterSpec__SynAssignment_10"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4086:1: rule__FilterSpec__SynAssignment_10 : ( ( '--syn' ) ) ;
    public final void rule__FilterSpec__SynAssignment_10() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4090:1: ( ( ( '--syn' ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4091:1: ( ( '--syn' ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4091:1: ( ( '--syn' ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4092:1: ( '--syn' )
            {
             before(grammarAccess.getFilterSpecAccess().getSynSynKeyword_10_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4093:1: ( '--syn' )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4094:1: '--syn'
            {
             before(grammarAccess.getFilterSpecAccess().getSynSynKeyword_10_0()); 
            match(input,56,FOLLOW_56_in_rule__FilterSpec__SynAssignment_108317); 
             after(grammarAccess.getFilterSpecAccess().getSynSynKeyword_10_0()); 

            }

             after(grammarAccess.getFilterSpecAccess().getSynSynKeyword_10_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__SynAssignment_10"


    // $ANTLR start "rule__FilterSpec__MatchesAssignment_11_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4109:1: rule__FilterSpec__MatchesAssignment_11_1 : ( ruleMatch ) ;
    public final void rule__FilterSpec__MatchesAssignment_11_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4113:1: ( ( ruleMatch ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4114:1: ( ruleMatch )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4114:1: ( ruleMatch )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4115:1: ruleMatch
            {
             before(grammarAccess.getFilterSpecAccess().getMatchesMatchParserRuleCall_11_1_0()); 
            pushFollow(FOLLOW_ruleMatch_in_rule__FilterSpec__MatchesAssignment_11_18356);
            ruleMatch();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getMatchesMatchParserRuleCall_11_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__MatchesAssignment_11_1"


    // $ANTLR start "rule__FilterSpec__StatesAssignment_12_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4124:1: rule__FilterSpec__StatesAssignment_12_1 : ( ruleState ) ;
    public final void rule__FilterSpec__StatesAssignment_12_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4128:1: ( ( ruleState ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4129:1: ( ruleState )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4129:1: ( ruleState )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4130:1: ruleState
            {
             before(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_12_1_0()); 
            pushFollow(FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_12_18387);
            ruleState();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_12_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__StatesAssignment_12_1"


    // $ANTLR start "rule__FilterSpec__StatesAssignment_12_2_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4139:1: rule__FilterSpec__StatesAssignment_12_2_1 : ( ruleState ) ;
    public final void rule__FilterSpec__StatesAssignment_12_2_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4143:1: ( ( ruleState ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4144:1: ( ruleState )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4144:1: ( ruleState )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4145:1: ruleState
            {
             before(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_12_2_1_0()); 
            pushFollow(FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_12_2_18418);
            ruleState();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_12_2_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__StatesAssignment_12_2_1"


    // $ANTLR start "rule__FilterSpec__DirAssignment_13_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4154:1: rule__FilterSpec__DirAssignment_13_1 : ( ruleDir ) ;
    public final void rule__FilterSpec__DirAssignment_13_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4158:1: ( ( ruleDir ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4159:1: ( ruleDir )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4159:1: ( ruleDir )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4160:1: ruleDir
            {
             before(grammarAccess.getFilterSpecAccess().getDirDirParserRuleCall_13_1_0()); 
            pushFollow(FOLLOW_ruleDir_in_rule__FilterSpec__DirAssignment_13_18449);
            ruleDir();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getDirDirParserRuleCall_13_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__DirAssignment_13_1"


    // $ANTLR start "rule__FilterSpec__StatusAssignment_14_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4169:1: rule__FilterSpec__StatusAssignment_14_1 : ( ruleStatus ) ;
    public final void rule__FilterSpec__StatusAssignment_14_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4173:1: ( ( ruleStatus ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4174:1: ( ruleStatus )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4174:1: ( ruleStatus )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4175:1: ruleStatus
            {
             before(grammarAccess.getFilterSpecAccess().getStatusStatusParserRuleCall_14_1_0()); 
            pushFollow(FOLLOW_ruleStatus_in_rule__FilterSpec__StatusAssignment_14_18480);
            ruleStatus();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getStatusStatusParserRuleCall_14_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__StatusAssignment_14_1"


    // $ANTLR start "rule__FilterSpec__StatesAssignment_15_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4184:1: rule__FilterSpec__StatesAssignment_15_1 : ( ruleState ) ;
    public final void rule__FilterSpec__StatesAssignment_15_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4188:1: ( ( ruleState ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4189:1: ( ruleState )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4189:1: ( ruleState )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4190:1: ruleState
            {
             before(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_15_1_0()); 
            pushFollow(FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_15_18511);
            ruleState();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_15_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__StatesAssignment_15_1"


    // $ANTLR start "rule__FilterSpec__StatesAssignment_15_2_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4199:1: rule__FilterSpec__StatesAssignment_15_2_1 : ( ruleState ) ;
    public final void rule__FilterSpec__StatesAssignment_15_2_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4203:1: ( ( ruleState ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4204:1: ( ruleState )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4204:1: ( ruleState )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4205:1: ruleState
            {
             before(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_15_2_1_0()); 
            pushFollow(FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_15_2_18542);
            ruleState();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getStatesStateParserRuleCall_15_2_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__StatesAssignment_15_2_1"


    // $ANTLR start "rule__FilterSpec__ExamFlagsAssignment_16_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4214:1: rule__FilterSpec__ExamFlagsAssignment_16_1 : ( ruleTCPFlag ) ;
    public final void rule__FilterSpec__ExamFlagsAssignment_16_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4218:1: ( ( ruleTCPFlag ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4219:1: ( ruleTCPFlag )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4219:1: ( ruleTCPFlag )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4220:1: ruleTCPFlag
            {
             before(grammarAccess.getFilterSpecAccess().getExamFlagsTCPFlagParserRuleCall_16_1_0()); 
            pushFollow(FOLLOW_ruleTCPFlag_in_rule__FilterSpec__ExamFlagsAssignment_16_18573);
            ruleTCPFlag();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getExamFlagsTCPFlagParserRuleCall_16_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__ExamFlagsAssignment_16_1"


    // $ANTLR start "rule__FilterSpec__ExamFlagsAssignment_16_2_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4229:1: rule__FilterSpec__ExamFlagsAssignment_16_2_1 : ( ruleTCPFlag ) ;
    public final void rule__FilterSpec__ExamFlagsAssignment_16_2_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4233:1: ( ( ruleTCPFlag ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4234:1: ( ruleTCPFlag )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4234:1: ( ruleTCPFlag )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4235:1: ruleTCPFlag
            {
             before(grammarAccess.getFilterSpecAccess().getExamFlagsTCPFlagParserRuleCall_16_2_1_0()); 
            pushFollow(FOLLOW_ruleTCPFlag_in_rule__FilterSpec__ExamFlagsAssignment_16_2_18604);
            ruleTCPFlag();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getExamFlagsTCPFlagParserRuleCall_16_2_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__ExamFlagsAssignment_16_2_1"


    // $ANTLR start "rule__FilterSpec__FlagsAssignment_16_3"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4244:1: rule__FilterSpec__FlagsAssignment_16_3 : ( ruleTCPFlag ) ;
    public final void rule__FilterSpec__FlagsAssignment_16_3() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4248:1: ( ( ruleTCPFlag ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4249:1: ( ruleTCPFlag )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4249:1: ( ruleTCPFlag )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4250:1: ruleTCPFlag
            {
             before(grammarAccess.getFilterSpecAccess().getFlagsTCPFlagParserRuleCall_16_3_0()); 
            pushFollow(FOLLOW_ruleTCPFlag_in_rule__FilterSpec__FlagsAssignment_16_38635);
            ruleTCPFlag();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getFlagsTCPFlagParserRuleCall_16_3_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__FlagsAssignment_16_3"


    // $ANTLR start "rule__FilterSpec__FlagsAssignment_16_4_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4259:1: rule__FilterSpec__FlagsAssignment_16_4_1 : ( ruleTCPFlag ) ;
    public final void rule__FilterSpec__FlagsAssignment_16_4_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4263:1: ( ( ruleTCPFlag ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4264:1: ( ruleTCPFlag )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4264:1: ( ruleTCPFlag )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4265:1: ruleTCPFlag
            {
             before(grammarAccess.getFilterSpecAccess().getFlagsTCPFlagParserRuleCall_16_4_1_0()); 
            pushFollow(FOLLOW_ruleTCPFlag_in_rule__FilterSpec__FlagsAssignment_16_4_18666);
            ruleTCPFlag();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getFlagsTCPFlagParserRuleCall_16_4_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__FlagsAssignment_16_4_1"


    // $ANTLR start "rule__FilterSpec__TargetAssignment_18"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4274:1: rule__FilterSpec__TargetAssignment_18 : ( ruleTarget ) ;
    public final void rule__FilterSpec__TargetAssignment_18() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4278:1: ( ( ruleTarget ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4279:1: ( ruleTarget )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4279:1: ( ruleTarget )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4280:1: ruleTarget
            {
             before(grammarAccess.getFilterSpecAccess().getTargetTargetParserRuleCall_18_0()); 
            pushFollow(FOLLOW_ruleTarget_in_rule__FilterSpec__TargetAssignment_188697);
            ruleTarget();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getTargetTargetParserRuleCall_18_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__TargetAssignment_18"


    // $ANTLR start "rule__FilterSpec__LpAssignment_19_1"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4289:1: rule__FilterSpec__LpAssignment_19_1 : ( ruleLP ) ;
    public final void rule__FilterSpec__LpAssignment_19_1() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4293:1: ( ( ruleLP ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4294:1: ( ruleLP )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4294:1: ( ruleLP )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4295:1: ruleLP
            {
             before(grammarAccess.getFilterSpecAccess().getLpLPParserRuleCall_19_1_0()); 
            pushFollow(FOLLOW_ruleLP_in_rule__FilterSpec__LpAssignment_19_18728);
            ruleLP();

            state._fsp--;

             after(grammarAccess.getFilterSpecAccess().getLpLPParserRuleCall_19_1_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__FilterSpec__LpAssignment_19_1"


    // $ANTLR start "rule__Interface__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4304:1: rule__Interface__NameAssignment : ( RULE_ID ) ;
    public final void rule__Interface__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4308:1: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4309:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4309:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4310:1: RULE_ID
            {
             before(grammarAccess.getInterfaceAccess().getNameIDTerminalRuleCall_0()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_rule__Interface__NameAssignment8759); 
             after(grammarAccess.getInterfaceAccess().getNameIDTerminalRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Interface__NameAssignment"


    // $ANTLR start "rule__LP__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4319:1: rule__LP__NameAssignment : ( RULE_STRING ) ;
    public final void rule__LP__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4323:1: ( ( RULE_STRING ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4324:1: ( RULE_STRING )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4324:1: ( RULE_STRING )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4325:1: RULE_STRING
            {
             before(grammarAccess.getLPAccess().getNameSTRINGTerminalRuleCall_0()); 
            match(input,RULE_STRING,FOLLOW_RULE_STRING_in_rule__LP__NameAssignment8790); 
             after(grammarAccess.getLPAccess().getNameSTRINGTerminalRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__LP__NameAssignment"


    // $ANTLR start "rule__Match__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4334:1: rule__Match__NameAssignment : ( ( rule__Match__NameAlternatives_0 ) ) ;
    public final void rule__Match__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4338:1: ( ( ( rule__Match__NameAlternatives_0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4339:1: ( ( rule__Match__NameAlternatives_0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4339:1: ( ( rule__Match__NameAlternatives_0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4340:1: ( rule__Match__NameAlternatives_0 )
            {
             before(grammarAccess.getMatchAccess().getNameAlternatives_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4341:1: ( rule__Match__NameAlternatives_0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4341:2: rule__Match__NameAlternatives_0
            {
            pushFollow(FOLLOW_rule__Match__NameAlternatives_0_in_rule__Match__NameAssignment8821);
            rule__Match__NameAlternatives_0();

            state._fsp--;


            }

             after(grammarAccess.getMatchAccess().getNameAlternatives_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Match__NameAssignment"


    // $ANTLR start "rule__State__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4350:1: rule__State__NameAssignment : ( ( rule__State__NameAlternatives_0 ) ) ;
    public final void rule__State__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4354:1: ( ( ( rule__State__NameAlternatives_0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4355:1: ( ( rule__State__NameAlternatives_0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4355:1: ( ( rule__State__NameAlternatives_0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4356:1: ( rule__State__NameAlternatives_0 )
            {
             before(grammarAccess.getStateAccess().getNameAlternatives_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4357:1: ( rule__State__NameAlternatives_0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4357:2: rule__State__NameAlternatives_0
            {
            pushFollow(FOLLOW_rule__State__NameAlternatives_0_in_rule__State__NameAssignment8854);
            rule__State__NameAlternatives_0();

            state._fsp--;


            }

             after(grammarAccess.getStateAccess().getNameAlternatives_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__State__NameAssignment"


    // $ANTLR start "rule__TCPFlag__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4366:1: rule__TCPFlag__NameAssignment : ( ( rule__TCPFlag__NameAlternatives_0 ) ) ;
    public final void rule__TCPFlag__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4370:1: ( ( ( rule__TCPFlag__NameAlternatives_0 ) ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4371:1: ( ( rule__TCPFlag__NameAlternatives_0 ) )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4371:1: ( ( rule__TCPFlag__NameAlternatives_0 ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4372:1: ( rule__TCPFlag__NameAlternatives_0 )
            {
             before(grammarAccess.getTCPFlagAccess().getNameAlternatives_0()); 
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4373:1: ( rule__TCPFlag__NameAlternatives_0 )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4373:2: rule__TCPFlag__NameAlternatives_0
            {
            pushFollow(FOLLOW_rule__TCPFlag__NameAlternatives_0_in_rule__TCPFlag__NameAssignment8887);
            rule__TCPFlag__NameAlternatives_0();

            state._fsp--;


            }

             after(grammarAccess.getTCPFlagAccess().getNameAlternatives_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__TCPFlag__NameAssignment"


    // $ANTLR start "rule__Chain__ChainNameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4382:1: rule__Chain__ChainNameAssignment : ( RULE_ID ) ;
    public final void rule__Chain__ChainNameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4386:1: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4387:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4387:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4388:1: RULE_ID
            {
             before(grammarAccess.getChainAccess().getChainNameIDTerminalRuleCall_0()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_rule__Chain__ChainNameAssignment8920); 
             after(grammarAccess.getChainAccess().getChainNameIDTerminalRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__Chain__ChainNameAssignment"


    // $ANTLR start "rule__ChainName__NameAssignment"
    // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4398:1: rule__ChainName__NameAssignment : ( RULE_ID ) ;
    public final void rule__ChainName__NameAssignment() throws RecognitionException {

        		int stackSize = keepStackSize();
            
        try {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4402:1: ( ( RULE_ID ) )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4403:1: ( RULE_ID )
            {
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4403:1: ( RULE_ID )
            // ../org.xtext.firewall.iptables.ui/src-gen/org/xtext/example/iptables/ui/contentassist/antlr/internal/InternalIptables.g:4404:1: RULE_ID
            {
             before(grammarAccess.getChainNameAccess().getNameIDTerminalRuleCall_0()); 
            match(input,RULE_ID,FOLLOW_RULE_ID_in_rule__ChainName__NameAssignment8952); 
             after(grammarAccess.getChainNameAccess().getNameIDTerminalRuleCall_0()); 

            }


            }

        }
        catch (RecognitionException re) {
            reportError(re);
            recover(input,re);
        }
        finally {

            	restoreStackSize(stackSize);

        }
        return ;
    }
    // $ANTLR end "rule__ChainName__NameAssignment"

    // Delegated rules


 

    public static final BitSet FOLLOW_ruleModel_in_entryRuleModel61 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleModel68 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Model__RulesAssignment_in_ruleModel94 = new BitSet(new long[]{0x0000001000000002L});
    public static final BitSet FOLLOW_ruleRule_in_entryRuleRule122 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleRule129 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Rule__Alternatives_in_ruleRule155 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilterDeclaration_in_entryRuleFilterDeclaration182 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleFilterDeclaration189 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterDeclaration__FilterAssignment_in_ruleFilterDeclaration215 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilteringSpec_in_entryRuleFilteringSpec242 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleFilteringSpec249 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilterSpec_in_ruleFilteringSpec275 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilterSpec_in_entryRuleFilterSpec301 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleFilterSpec308 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__0_in_ruleFilterSpec334 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleInterface_in_entryRuleInterface361 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleInterface368 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Interface__NameAssignment_in_ruleInterface394 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleLP_in_entryRuleLP421 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleLP428 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__LP__NameAssignment_in_ruleLP454 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleMatch_in_entryRuleMatch481 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleMatch488 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Match__NameAssignment_in_ruleMatch514 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleDir_in_entryRuleDir541 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleDir548 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_ruleDir574 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStatus_in_entryRuleStatus600 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleStatus607 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_ruleStatus633 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleConntrack_in_entryRuleConntrack659 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleConntrack666 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_11_in_ruleConntrack693 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStateMatch_in_entryRuleStateMatch721 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleStateMatch728 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_12_in_ruleStateMatch755 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleState_in_entryRuleState783 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleState790 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__State__NameAssignment_in_ruleState816 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStateFulMatchStates_in_entryRuleStateFulMatchStates843 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleStateFulMatchStates850 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__StateFulMatchStates__Alternatives_in_ruleStateFulMatchStates876 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNormalMatchStates_in_entryRuleNormalMatchStates903 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleNormalMatchStates910 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNew_in_ruleNormalMatchStates936 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNew_in_entryRuleNew962 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleNew969 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_13_in_ruleNew996 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNoneS_in_entryRuleNoneS1024 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleNoneS1031 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_14_in_ruleNoneS1058 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSynSent_in_entryRuleSynSent1086 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleSynSent1093 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_15_in_ruleSynSent1120 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSynRecv_in_entryRuleSynRecv1148 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleSynRecv1155 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_16_in_ruleSynRecv1182 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleEstablished_in_entryRuleEstablished1210 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleEstablished1217 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_17_in_ruleEstablished1244 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFinWait_in_entryRuleFinWait1272 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleFinWait1279 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_18_in_ruleFinWait1306 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleCloseWait_in_entryRuleCloseWait1334 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleCloseWait1341 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_19_in_ruleCloseWait1368 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleLastAck_in_entryRuleLastAck1396 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleLastAck1403 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_20_in_ruleLastAck1430 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTimeWait_in_entryRuleTimeWait1458 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleTimeWait1465 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_21_in_ruleTimeWait1492 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleClose_in_entryRuleClose1520 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleClose1527 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_22_in_ruleClose1554 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTCPFlag_in_entryRuleTCPFlag1582 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleTCPFlag1589 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__TCPFlag__NameAssignment_in_ruleTCPFlag1615 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSyn_in_entryRuleSyn1642 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleSyn1649 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_23_in_ruleSyn1676 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleAck_in_entryRuleAck1704 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleAck1711 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_24_in_ruleAck1738 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFin_in_entryRuleFin1766 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleFin1773 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_25_in_ruleFin1800 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleRst_in_entryRuleRst1828 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleRst1835 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_26_in_ruleRst1862 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleAll_in_entryRuleAll1890 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleAll1897 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_27_in_ruleAll1924 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNone_in_entryRuleNone1952 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleNone1959 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_14_in_ruleNone1986 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rulePsh_in_entryRulePsh2014 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRulePsh2021 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_28_in_rulePsh2048 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleUrg_in_entryRuleUrg2076 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleUrg2083 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_29_in_ruleUrg2110 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleProtocol_in_entryRuleProtocol2138 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleProtocol2145 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Protocol__Alternatives_in_ruleProtocol2171 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTcp_in_entryRuleTcp2198 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleTcp2205 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_30_in_ruleTcp2232 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleUdp_in_entryRuleUdp2260 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleUdp2267 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_31_in_ruleUdp2294 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIcmp_in_entryRuleIcmp2322 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleIcmp2329 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_32_in_ruleIcmp2356 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTarget_in_entryRuleTarget2384 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleTarget2391 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_ruleTarget2417 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChain_in_entryRuleChain2443 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleChain2450 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Chain__ChainNameAssignment_in_ruleChain2476 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChainDeclaration_in_entryRuleChainDeclaration2505 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleChainDeclaration2512 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__0_in_ruleChainDeclaration2538 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChainName_in_entryRuleChainName2565 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleChainName2572 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__ChainName__NameAssignment_in_ruleChainName2598 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIPExpr_in_entryRuleIPExpr2625 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleIPExpr2632 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__0_in_ruleIPExpr2658 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleipByteExpr_in_entryRuleipByteExpr2685 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleipByteExpr2692 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_INT_in_ruleipByteExpr2718 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIpRangeExpr_in_entryRuleIpRangeExpr2744 = new BitSet(new long[]{0x0000000000000000L});
    public static final BitSet FOLLOW_EOF_in_entryRuleIpRangeExpr2751 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IpRangeExpr__Group__0_in_ruleIpRangeExpr2777 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Rule__DeclarationAssignment_0_in_rule__Rule__Alternatives2813 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Rule__FilterAssignment_1_in_rule__Rule__Alternatives2831 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_33_in_rule__FilterSpec__OptionAlternatives_1_02865 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_34_in_rule__FilterSpec__OptionAlternatives_1_02885 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_35_in_rule__FilterSpec__OptionAlternatives_1_02905 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleConntrack_in_rule__Match__NameAlternatives_02939 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStateMatch_in_rule__Match__NameAlternatives_02956 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNormalMatchStates_in_rule__State__NameAlternatives_02988 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStateFulMatchStates_in_rule__State__NameAlternatives_03005 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNoneS_in_rule__StateFulMatchStates__Alternatives3037 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSynSent_in_rule__StateFulMatchStates__Alternatives3054 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSynRecv_in_rule__StateFulMatchStates__Alternatives3071 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleEstablished_in_rule__StateFulMatchStates__Alternatives3088 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFinWait_in_rule__StateFulMatchStates__Alternatives3105 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleCloseWait_in_rule__StateFulMatchStates__Alternatives3122 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleLastAck_in_rule__StateFulMatchStates__Alternatives3139 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTimeWait_in_rule__StateFulMatchStates__Alternatives3156 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleClose_in_rule__StateFulMatchStates__Alternatives3173 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleSyn_in_rule__TCPFlag__NameAlternatives_03205 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleAck_in_rule__TCPFlag__NameAlternatives_03222 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFin_in_rule__TCPFlag__NameAlternatives_03239 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleRst_in_rule__TCPFlag__NameAlternatives_03256 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleAll_in_rule__TCPFlag__NameAlternatives_03273 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleNone_in_rule__TCPFlag__NameAlternatives_03290 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rulePsh_in_rule__TCPFlag__NameAlternatives_03307 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleUrg_in_rule__TCPFlag__NameAlternatives_03324 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTcp_in_rule__Protocol__Alternatives3356 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleUdp_in_rule__Protocol__Alternatives3373 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIcmp_in_rule__Protocol__Alternatives3390 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__0__Impl_in_rule__FilterSpec__Group__03420 = new BitSet(new long[]{0x0000000E00000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__1_in_rule__FilterSpec__Group__03423 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_36_in_rule__FilterSpec__Group__0__Impl3451 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__1__Impl_in_rule__FilterSpec__Group__13482 = new BitSet(new long[]{0x0000000000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__2_in_rule__FilterSpec__Group__13485 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__OptionAssignment_1_in_rule__FilterSpec__Group__1__Impl3512 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__2__Impl_in_rule__FilterSpec__Group__23542 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__3_in_rule__FilterSpec__Group__23545 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__ChainAssignment_2_in_rule__FilterSpec__Group__2__Impl3572 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__3__Impl_in_rule__FilterSpec__Group__33602 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__4_in_rule__FilterSpec__Group__33605 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_3__0_in_rule__FilterSpec__Group__3__Impl3632 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__4__Impl_in_rule__FilterSpec__Group__43663 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__5_in_rule__FilterSpec__Group__43666 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_4__0_in_rule__FilterSpec__Group__4__Impl3693 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__5__Impl_in_rule__FilterSpec__Group__53724 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__6_in_rule__FilterSpec__Group__53727 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_5__0_in_rule__FilterSpec__Group__5__Impl3754 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__6__Impl_in_rule__FilterSpec__Group__63785 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__7_in_rule__FilterSpec__Group__63788 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_6__0_in_rule__FilterSpec__Group__6__Impl3815 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__7__Impl_in_rule__FilterSpec__Group__73846 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__8_in_rule__FilterSpec__Group__73849 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_7__0_in_rule__FilterSpec__Group__7__Impl3876 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__8__Impl_in_rule__FilterSpec__Group__83907 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__9_in_rule__FilterSpec__Group__83910 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_8__0_in_rule__FilterSpec__Group__8__Impl3937 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__9__Impl_in_rule__FilterSpec__Group__93968 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__10_in_rule__FilterSpec__Group__93971 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__NegAssignment_9_in_rule__FilterSpec__Group__9__Impl3998 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__10__Impl_in_rule__FilterSpec__Group__104029 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__11_in_rule__FilterSpec__Group__104032 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__SynAssignment_10_in_rule__FilterSpec__Group__10__Impl4059 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__11__Impl_in_rule__FilterSpec__Group__114090 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__12_in_rule__FilterSpec__Group__114093 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_11__0_in_rule__FilterSpec__Group__11__Impl4120 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__12__Impl_in_rule__FilterSpec__Group__124151 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__13_in_rule__FilterSpec__Group__124154 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__0_in_rule__FilterSpec__Group__12__Impl4181 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__13__Impl_in_rule__FilterSpec__Group__134212 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__14_in_rule__FilterSpec__Group__134215 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_13__0_in_rule__FilterSpec__Group__13__Impl4242 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__14__Impl_in_rule__FilterSpec__Group__144273 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__15_in_rule__FilterSpec__Group__144276 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_14__0_in_rule__FilterSpec__Group__14__Impl4303 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__15__Impl_in_rule__FilterSpec__Group__154334 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__16_in_rule__FilterSpec__Group__154337 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__0_in_rule__FilterSpec__Group__15__Impl4364 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__16__Impl_in_rule__FilterSpec__Group__164395 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__17_in_rule__FilterSpec__Group__164398 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__0_in_rule__FilterSpec__Group__16__Impl4425 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__17__Impl_in_rule__FilterSpec__Group__174456 = new BitSet(new long[]{0x0187BFE000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__18_in_rule__FilterSpec__Group__174459 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_37_in_rule__FilterSpec__Group__17__Impl4488 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__18__Impl_in_rule__FilterSpec__Group__184521 = new BitSet(new long[]{0x0008000000000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__19_in_rule__FilterSpec__Group__184524 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__TargetAssignment_18_in_rule__FilterSpec__Group__18__Impl4551 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group__19__Impl_in_rule__FilterSpec__Group__194581 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_19__0_in_rule__FilterSpec__Group__19__Impl4608 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_3__0__Impl_in_rule__FilterSpec__Group_3__04679 = new BitSet(new long[]{0x00000001C0000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_3__1_in_rule__FilterSpec__Group_3__04682 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_38_in_rule__FilterSpec__Group_3__0__Impl4710 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_3__1__Impl_in_rule__FilterSpec__Group_3__14741 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__ProtocolAssignment_3_1_in_rule__FilterSpec__Group_3__1__Impl4768 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_4__0__Impl_in_rule__FilterSpec__Group_4__04802 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_4__1_in_rule__FilterSpec__Group_4__04805 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_39_in_rule__FilterSpec__Group_4__0__Impl4833 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_4__1__Impl_in_rule__FilterSpec__Group_4__14864 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__IpAssignment_4_1_in_rule__FilterSpec__Group_4__1__Impl4891 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_5__0__Impl_in_rule__FilterSpec__Group_5__04925 = new BitSet(new long[]{0x0000000000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_5__1_in_rule__FilterSpec__Group_5__04928 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_40_in_rule__FilterSpec__Group_5__0__Impl4956 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_5__1__Impl_in_rule__FilterSpec__Group_5__14987 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__InterfaceAssignment_5_1_in_rule__FilterSpec__Group_5__1__Impl5014 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_6__0__Impl_in_rule__FilterSpec__Group_6__05048 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_6__1_in_rule__FilterSpec__Group_6__05051 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_41_in_rule__FilterSpec__Group_6__0__Impl5079 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_6__1__Impl_in_rule__FilterSpec__Group_6__15110 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__IpDstAssignment_6_1_in_rule__FilterSpec__Group_6__1__Impl5137 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_7__0__Impl_in_rule__FilterSpec__Group_7__05171 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_7__1_in_rule__FilterSpec__Group_7__05174 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_42_in_rule__FilterSpec__Group_7__0__Impl5202 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_7__1__Impl_in_rule__FilterSpec__Group_7__15233 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__SourcePortAssignment_7_1_in_rule__FilterSpec__Group_7__1__Impl5260 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_8__0__Impl_in_rule__FilterSpec__Group_8__05294 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_8__1_in_rule__FilterSpec__Group_8__05297 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_43_in_rule__FilterSpec__Group_8__0__Impl5325 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_8__1__Impl_in_rule__FilterSpec__Group_8__15356 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__DestinationPortAssignment_8_1_in_rule__FilterSpec__Group_8__1__Impl5383 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_11__0__Impl_in_rule__FilterSpec__Group_11__05417 = new BitSet(new long[]{0x0000000000001800L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_11__1_in_rule__FilterSpec__Group_11__05420 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_44_in_rule__FilterSpec__Group_11__0__Impl5448 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_11__1__Impl_in_rule__FilterSpec__Group_11__15479 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__MatchesAssignment_11_1_in_rule__FilterSpec__Group_11__1__Impl5506 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__0__Impl_in_rule__FilterSpec__Group_12__05540 = new BitSet(new long[]{0x00000000007FE000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__1_in_rule__FilterSpec__Group_12__05543 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_45_in_rule__FilterSpec__Group_12__0__Impl5571 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__1__Impl_in_rule__FilterSpec__Group_12__15602 = new BitSet(new long[]{0x0000400000000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__2_in_rule__FilterSpec__Group_12__15605 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__StatesAssignment_12_1_in_rule__FilterSpec__Group_12__1__Impl5632 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12__2__Impl_in_rule__FilterSpec__Group_12__25662 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12_2__0_in_rule__FilterSpec__Group_12__2__Impl5689 = new BitSet(new long[]{0x0000400000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12_2__0__Impl_in_rule__FilterSpec__Group_12_2__05726 = new BitSet(new long[]{0x00000000007FE000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12_2__1_in_rule__FilterSpec__Group_12_2__05729 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_46_in_rule__FilterSpec__Group_12_2__0__Impl5757 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_12_2__1__Impl_in_rule__FilterSpec__Group_12_2__15788 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__StatesAssignment_12_2_1_in_rule__FilterSpec__Group_12_2__1__Impl5815 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_13__0__Impl_in_rule__FilterSpec__Group_13__05849 = new BitSet(new long[]{0x0000000000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_13__1_in_rule__FilterSpec__Group_13__05852 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_47_in_rule__FilterSpec__Group_13__0__Impl5880 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_13__1__Impl_in_rule__FilterSpec__Group_13__15911 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__DirAssignment_13_1_in_rule__FilterSpec__Group_13__1__Impl5938 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_14__0__Impl_in_rule__FilterSpec__Group_14__05972 = new BitSet(new long[]{0x0000000000000010L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_14__1_in_rule__FilterSpec__Group_14__05975 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_48_in_rule__FilterSpec__Group_14__0__Impl6003 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_14__1__Impl_in_rule__FilterSpec__Group_14__16034 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__StatusAssignment_14_1_in_rule__FilterSpec__Group_14__1__Impl6061 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__0__Impl_in_rule__FilterSpec__Group_15__06095 = new BitSet(new long[]{0x00000000007FE000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__1_in_rule__FilterSpec__Group_15__06098 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_49_in_rule__FilterSpec__Group_15__0__Impl6126 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__1__Impl_in_rule__FilterSpec__Group_15__16157 = new BitSet(new long[]{0x0000400000000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__2_in_rule__FilterSpec__Group_15__16160 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__StatesAssignment_15_1_in_rule__FilterSpec__Group_15__1__Impl6187 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15__2__Impl_in_rule__FilterSpec__Group_15__26217 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15_2__0_in_rule__FilterSpec__Group_15__2__Impl6244 = new BitSet(new long[]{0x0000400000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15_2__0__Impl_in_rule__FilterSpec__Group_15_2__06281 = new BitSet(new long[]{0x00000000007FE000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15_2__1_in_rule__FilterSpec__Group_15_2__06284 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_46_in_rule__FilterSpec__Group_15_2__0__Impl6312 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_15_2__1__Impl_in_rule__FilterSpec__Group_15_2__16343 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__StatesAssignment_15_2_1_in_rule__FilterSpec__Group_15_2__1__Impl6370 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__0__Impl_in_rule__FilterSpec__Group_16__06404 = new BitSet(new long[]{0x000000003F804000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__1_in_rule__FilterSpec__Group_16__06407 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_50_in_rule__FilterSpec__Group_16__0__Impl6435 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__1__Impl_in_rule__FilterSpec__Group_16__16466 = new BitSet(new long[]{0x000040003F804000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__2_in_rule__FilterSpec__Group_16__16469 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__ExamFlagsAssignment_16_1_in_rule__FilterSpec__Group_16__1__Impl6496 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__2__Impl_in_rule__FilterSpec__Group_16__26526 = new BitSet(new long[]{0x000040003F804000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__3_in_rule__FilterSpec__Group_16__26529 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_2__0_in_rule__FilterSpec__Group_16__2__Impl6556 = new BitSet(new long[]{0x0000400000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__3__Impl_in_rule__FilterSpec__Group_16__36587 = new BitSet(new long[]{0x0000400000000000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__4_in_rule__FilterSpec__Group_16__36590 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__FlagsAssignment_16_3_in_rule__FilterSpec__Group_16__3__Impl6617 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16__4__Impl_in_rule__FilterSpec__Group_16__46647 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_4__0_in_rule__FilterSpec__Group_16__4__Impl6674 = new BitSet(new long[]{0x0000400000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_2__0__Impl_in_rule__FilterSpec__Group_16_2__06715 = new BitSet(new long[]{0x000000003F804000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_2__1_in_rule__FilterSpec__Group_16_2__06718 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_46_in_rule__FilterSpec__Group_16_2__0__Impl6746 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_2__1__Impl_in_rule__FilterSpec__Group_16_2__16777 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__ExamFlagsAssignment_16_2_1_in_rule__FilterSpec__Group_16_2__1__Impl6804 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_4__0__Impl_in_rule__FilterSpec__Group_16_4__06838 = new BitSet(new long[]{0x000000003F804000L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_4__1_in_rule__FilterSpec__Group_16_4__06841 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_46_in_rule__FilterSpec__Group_16_4__0__Impl6869 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_16_4__1__Impl_in_rule__FilterSpec__Group_16_4__16900 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__FlagsAssignment_16_4_1_in_rule__FilterSpec__Group_16_4__1__Impl6927 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_19__0__Impl_in_rule__FilterSpec__Group_19__06961 = new BitSet(new long[]{0x0000000000000040L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_19__1_in_rule__FilterSpec__Group_19__06964 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_51_in_rule__FilterSpec__Group_19__0__Impl6992 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__Group_19__1__Impl_in_rule__FilterSpec__Group_19__17023 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__LpAssignment_19_1_in_rule__FilterSpec__Group_19__1__Impl7050 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__0__Impl_in_rule__ChainDeclaration__Group__07084 = new BitSet(new long[]{0x0010000000000000L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__1_in_rule__ChainDeclaration__Group__07087 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_36_in_rule__ChainDeclaration__Group__0__Impl7115 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__1__Impl_in_rule__ChainDeclaration__Group__17146 = new BitSet(new long[]{0x0000000000000010L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__2_in_rule__ChainDeclaration__Group__17149 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_52_in_rule__ChainDeclaration__Group__1__Impl7177 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__ChainDeclaration__Group__2__Impl_in_rule__ChainDeclaration__Group__27208 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChainName_in_rule__ChainDeclaration__Group__2__Impl7235 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__0__Impl_in_rule__IPExpr__Group__07270 = new BitSet(new long[]{0x0020000000000000L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__1_in_rule__IPExpr__Group__07273 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__0__Impl7300 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__1__Impl_in_rule__IPExpr__Group__17329 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__2_in_rule__IPExpr__Group__17332 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_53_in_rule__IPExpr__Group__1__Impl7360 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__2__Impl_in_rule__IPExpr__Group__27391 = new BitSet(new long[]{0x0020000000000000L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__3_in_rule__IPExpr__Group__27394 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__2__Impl7421 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__3__Impl_in_rule__IPExpr__Group__37450 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__4_in_rule__IPExpr__Group__37453 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_53_in_rule__IPExpr__Group__3__Impl7481 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__4__Impl_in_rule__IPExpr__Group__47512 = new BitSet(new long[]{0x0020000000000000L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__5_in_rule__IPExpr__Group__47515 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__4__Impl7542 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__5__Impl_in_rule__IPExpr__Group__57571 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__6_in_rule__IPExpr__Group__57574 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_53_in_rule__IPExpr__Group__5__Impl7602 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__6__Impl_in_rule__IPExpr__Group__67633 = new BitSet(new long[]{0x0040000000000000L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__7_in_rule__IPExpr__Group__67636 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleipByteExpr_in_rule__IPExpr__Group__6__Impl7663 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IPExpr__Group__7__Impl_in_rule__IPExpr__Group__77692 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIpRangeExpr_in_rule__IPExpr__Group__7__Impl7720 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IpRangeExpr__Group__0__Impl_in_rule__IpRangeExpr__Group__07767 = new BitSet(new long[]{0x0000000000000020L});
    public static final BitSet FOLLOW_rule__IpRangeExpr__Group__1_in_rule__IpRangeExpr__Group__07770 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_54_in_rule__IpRangeExpr__Group__0__Impl7798 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__IpRangeExpr__Group__1__Impl_in_rule__IpRangeExpr__Group__17829 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_INT_in_rule__IpRangeExpr__Group__1__Impl7856 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleRule_in_rule__Model__RulesAssignment7894 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChainDeclaration_in_rule__Rule__DeclarationAssignment_07925 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilterDeclaration_in_rule__Rule__FilterAssignment_17956 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleFilteringSpec_in_rule__FilterDeclaration__FilterAssignment7987 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__FilterSpec__OptionAlternatives_1_0_in_rule__FilterSpec__OptionAssignment_18018 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleChain_in_rule__FilterSpec__ChainAssignment_28051 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleProtocol_in_rule__FilterSpec__ProtocolAssignment_3_18082 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIPExpr_in_rule__FilterSpec__IpAssignment_4_18113 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleInterface_in_rule__FilterSpec__InterfaceAssignment_5_18144 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleIPExpr_in_rule__FilterSpec__IpDstAssignment_6_18175 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_INT_in_rule__FilterSpec__SourcePortAssignment_7_18206 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_INT_in_rule__FilterSpec__DestinationPortAssignment_8_18237 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_55_in_rule__FilterSpec__NegAssignment_98273 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_56_in_rule__FilterSpec__SynAssignment_108317 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleMatch_in_rule__FilterSpec__MatchesAssignment_11_18356 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_12_18387 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_12_2_18418 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleDir_in_rule__FilterSpec__DirAssignment_13_18449 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleStatus_in_rule__FilterSpec__StatusAssignment_14_18480 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_15_18511 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleState_in_rule__FilterSpec__StatesAssignment_15_2_18542 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTCPFlag_in_rule__FilterSpec__ExamFlagsAssignment_16_18573 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTCPFlag_in_rule__FilterSpec__ExamFlagsAssignment_16_2_18604 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTCPFlag_in_rule__FilterSpec__FlagsAssignment_16_38635 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTCPFlag_in_rule__FilterSpec__FlagsAssignment_16_4_18666 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleTarget_in_rule__FilterSpec__TargetAssignment_188697 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_ruleLP_in_rule__FilterSpec__LpAssignment_19_18728 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_rule__Interface__NameAssignment8759 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_STRING_in_rule__LP__NameAssignment8790 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__Match__NameAlternatives_0_in_rule__Match__NameAssignment8821 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__State__NameAlternatives_0_in_rule__State__NameAssignment8854 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_rule__TCPFlag__NameAlternatives_0_in_rule__TCPFlag__NameAssignment8887 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_rule__Chain__ChainNameAssignment8920 = new BitSet(new long[]{0x0000000000000002L});
    public static final BitSet FOLLOW_RULE_ID_in_rule__ChainName__NameAssignment8952 = new BitSet(new long[]{0x0000000000000002L});

}