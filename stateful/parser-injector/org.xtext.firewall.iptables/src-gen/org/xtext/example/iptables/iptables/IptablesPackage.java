/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EAttribute;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EReference;

/**
 * <!-- begin-user-doc -->
 * The <b>Package</b> for the model.
 * It contains accessors for the meta objects to represent
 * <ul>
 *   <li>each class,</li>
 *   <li>each feature of each class,</li>
 *   <li>each enum,</li>
 *   <li>and each data type</li>
 * </ul>
 * <!-- end-user-doc -->
 * @see org.xtext.example.iptables.iptables.IptablesFactory
 * @model kind="package"
 * @generated
 */
public interface IptablesPackage extends EPackage
{
  /**
   * The package name.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  String eNAME = "iptables";

  /**
   * The package namespace URI.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  String eNS_URI = "http://www.xtext.org/example/iptables/Iptables";

  /**
   * The package namespace name.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  String eNS_PREFIX = "iptables";

  /**
   * The singleton instance of the package.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  IptablesPackage eINSTANCE = org.xtext.example.iptables.iptables.impl.IptablesPackageImpl.init();

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.ModelImpl <em>Model</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.ModelImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getModel()
   * @generated
   */
  int MODEL = 0;

  /**
   * The feature id for the '<em><b>Rules</b></em>' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int MODEL__RULES = 0;

  /**
   * The number of structural features of the '<em>Model</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int MODEL_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.RuleImpl <em>Rule</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.RuleImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getRule()
   * @generated
   */
  int RULE = 1;

  /**
   * The feature id for the '<em><b>Declaration</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int RULE__DECLARATION = 0;

  /**
   * The feature id for the '<em><b>Filter</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int RULE__FILTER = 1;

  /**
   * The number of structural features of the '<em>Rule</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int RULE_FEATURE_COUNT = 2;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.FilterDeclarationImpl <em>Filter Declaration</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.FilterDeclarationImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilterDeclaration()
   * @generated
   */
  int FILTER_DECLARATION = 2;

  /**
   * The feature id for the '<em><b>Filter</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_DECLARATION__FILTER = 0;

  /**
   * The number of structural features of the '<em>Filter Declaration</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_DECLARATION_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.FilteringSpecImpl <em>Filtering Spec</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.FilteringSpecImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilteringSpec()
   * @generated
   */
  int FILTERING_SPEC = 3;

  /**
   * The number of structural features of the '<em>Filtering Spec</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTERING_SPEC_FEATURE_COUNT = 0;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl <em>Filter Spec</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.FilterSpecImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilterSpec()
   * @generated
   */
  int FILTER_SPEC = 4;

  /**
   * The feature id for the '<em><b>Option</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__OPTION = FILTERING_SPEC_FEATURE_COUNT + 0;

  /**
   * The feature id for the '<em><b>Chain</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__CHAIN = FILTERING_SPEC_FEATURE_COUNT + 1;

  /**
   * The feature id for the '<em><b>Protocol</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__PROTOCOL = FILTERING_SPEC_FEATURE_COUNT + 2;

  /**
   * The feature id for the '<em><b>Ip</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__IP = FILTERING_SPEC_FEATURE_COUNT + 3;

  /**
   * The feature id for the '<em><b>Interface</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__INTERFACE = FILTERING_SPEC_FEATURE_COUNT + 4;

  /**
   * The feature id for the '<em><b>Ip Dst</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__IP_DST = FILTERING_SPEC_FEATURE_COUNT + 5;

  /**
   * The feature id for the '<em><b>Source Port</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__SOURCE_PORT = FILTERING_SPEC_FEATURE_COUNT + 6;

  /**
   * The feature id for the '<em><b>Destination Port</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__DESTINATION_PORT = FILTERING_SPEC_FEATURE_COUNT + 7;

  /**
   * The feature id for the '<em><b>Neg</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__NEG = FILTERING_SPEC_FEATURE_COUNT + 8;

  /**
   * The feature id for the '<em><b>Syn</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__SYN = FILTERING_SPEC_FEATURE_COUNT + 9;

  /**
   * The feature id for the '<em><b>Matches</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__MATCHES = FILTERING_SPEC_FEATURE_COUNT + 10;

  /**
   * The feature id for the '<em><b>States</b></em>' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__STATES = FILTERING_SPEC_FEATURE_COUNT + 11;

  /**
   * The feature id for the '<em><b>Dir</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__DIR = FILTERING_SPEC_FEATURE_COUNT + 12;

  /**
   * The feature id for the '<em><b>Status</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__STATUS = FILTERING_SPEC_FEATURE_COUNT + 13;

  /**
   * The feature id for the '<em><b>Exam Flags</b></em>' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__EXAM_FLAGS = FILTERING_SPEC_FEATURE_COUNT + 14;

  /**
   * The feature id for the '<em><b>Flags</b></em>' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__FLAGS = FILTERING_SPEC_FEATURE_COUNT + 15;

  /**
   * The feature id for the '<em><b>Target</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__TARGET = FILTERING_SPEC_FEATURE_COUNT + 16;

  /**
   * The feature id for the '<em><b>Lp</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC__LP = FILTERING_SPEC_FEATURE_COUNT + 17;

  /**
   * The number of structural features of the '<em>Filter Spec</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int FILTER_SPEC_FEATURE_COUNT = FILTERING_SPEC_FEATURE_COUNT + 18;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.InterfaceImpl <em>Interface</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.InterfaceImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getInterface()
   * @generated
   */
  int INTERFACE = 5;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int INTERFACE__NAME = 0;

  /**
   * The number of structural features of the '<em>Interface</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int INTERFACE_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.LPImpl <em>LP</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.LPImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getLP()
   * @generated
   */
  int LP = 6;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int LP__NAME = 0;

  /**
   * The number of structural features of the '<em>LP</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int LP_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.MatchImpl <em>Match</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.MatchImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getMatch()
   * @generated
   */
  int MATCH = 7;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int MATCH__NAME = 0;

  /**
   * The number of structural features of the '<em>Match</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int MATCH_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.StateImpl <em>State</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.StateImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getState()
   * @generated
   */
  int STATE = 8;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int STATE__NAME = 0;

  /**
   * The number of structural features of the '<em>State</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int STATE_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.TCPFlagImpl <em>TCP Flag</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.TCPFlagImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getTCPFlag()
   * @generated
   */
  int TCP_FLAG = 9;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int TCP_FLAG__NAME = 0;

  /**
   * The number of structural features of the '<em>TCP Flag</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int TCP_FLAG_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.ChainImpl <em>Chain</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.ChainImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChain()
   * @generated
   */
  int CHAIN = 10;

  /**
   * The feature id for the '<em><b>Chain Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CHAIN__CHAIN_NAME = 0;

  /**
   * The number of structural features of the '<em>Chain</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CHAIN_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.CustomChainImpl <em>Custom Chain</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.CustomChainImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getCustomChain()
   * @generated
   */
  int CUSTOM_CHAIN = 11;

  /**
   * The feature id for the '<em><b>Name</b></em>' reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CUSTOM_CHAIN__NAME = 0;

  /**
   * The number of structural features of the '<em>Custom Chain</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CUSTOM_CHAIN_FEATURE_COUNT = 1;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.ChainDeclarationImpl <em>Chain Declaration</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.ChainDeclarationImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChainDeclaration()
   * @generated
   */
  int CHAIN_DECLARATION = 12;

  /**
   * The number of structural features of the '<em>Chain Declaration</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CHAIN_DECLARATION_FEATURE_COUNT = 0;

  /**
   * The meta object id for the '{@link org.xtext.example.iptables.iptables.impl.ChainNameImpl <em>Chain Name</em>}' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see org.xtext.example.iptables.iptables.impl.ChainNameImpl
   * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChainName()
   * @generated
   */
  int CHAIN_NAME = 13;

  /**
   * The feature id for the '<em><b>Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CHAIN_NAME__NAME = CHAIN_DECLARATION_FEATURE_COUNT + 0;

  /**
   * The number of structural features of the '<em>Chain Name</em>' class.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   * @ordered
   */
  int CHAIN_NAME_FEATURE_COUNT = CHAIN_DECLARATION_FEATURE_COUNT + 1;


  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.Model <em>Model</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Model</em>'.
   * @see org.xtext.example.iptables.iptables.Model
   * @generated
   */
  EClass getModel();

  /**
   * Returns the meta object for the containment reference list '{@link org.xtext.example.iptables.iptables.Model#getRules <em>Rules</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference list '<em>Rules</em>'.
   * @see org.xtext.example.iptables.iptables.Model#getRules()
   * @see #getModel()
   * @generated
   */
  EReference getModel_Rules();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.Rule <em>Rule</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Rule</em>'.
   * @see org.xtext.example.iptables.iptables.Rule
   * @generated
   */
  EClass getRule();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.Rule#getDeclaration <em>Declaration</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Declaration</em>'.
   * @see org.xtext.example.iptables.iptables.Rule#getDeclaration()
   * @see #getRule()
   * @generated
   */
  EReference getRule_Declaration();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.Rule#getFilter <em>Filter</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Filter</em>'.
   * @see org.xtext.example.iptables.iptables.Rule#getFilter()
   * @see #getRule()
   * @generated
   */
  EReference getRule_Filter();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.FilterDeclaration <em>Filter Declaration</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Filter Declaration</em>'.
   * @see org.xtext.example.iptables.iptables.FilterDeclaration
   * @generated
   */
  EClass getFilterDeclaration();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.FilterDeclaration#getFilter <em>Filter</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Filter</em>'.
   * @see org.xtext.example.iptables.iptables.FilterDeclaration#getFilter()
   * @see #getFilterDeclaration()
   * @generated
   */
  EReference getFilterDeclaration_Filter();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.FilteringSpec <em>Filtering Spec</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Filtering Spec</em>'.
   * @see org.xtext.example.iptables.iptables.FilteringSpec
   * @generated
   */
  EClass getFilteringSpec();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.FilterSpec <em>Filter Spec</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Filter Spec</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec
   * @generated
   */
  EClass getFilterSpec();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getOption <em>Option</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Option</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getOption()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Option();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.FilterSpec#getChain <em>Chain</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Chain</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getChain()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_Chain();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getProtocol <em>Protocol</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Protocol</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getProtocol()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Protocol();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getIp <em>Ip</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Ip</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getIp()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Ip();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.FilterSpec#getInterface <em>Interface</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Interface</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getInterface()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_Interface();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getIpDst <em>Ip Dst</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Ip Dst</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getIpDst()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_IpDst();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getSourcePort <em>Source Port</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Source Port</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getSourcePort()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_SourcePort();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getDestinationPort <em>Destination Port</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Destination Port</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getDestinationPort()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_DestinationPort();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#isNeg <em>Neg</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Neg</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#isNeg()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Neg();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#isSyn <em>Syn</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Syn</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#isSyn()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Syn();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.FilterSpec#getMatches <em>Matches</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Matches</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getMatches()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_Matches();

  /**
   * Returns the meta object for the containment reference list '{@link org.xtext.example.iptables.iptables.FilterSpec#getStates <em>States</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference list '<em>States</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getStates()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_States();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getDir <em>Dir</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Dir</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getDir()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Dir();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getStatus <em>Status</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Status</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getStatus()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Status();

  /**
   * Returns the meta object for the containment reference list '{@link org.xtext.example.iptables.iptables.FilterSpec#getExamFlags <em>Exam Flags</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference list '<em>Exam Flags</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getExamFlags()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_ExamFlags();

  /**
   * Returns the meta object for the containment reference list '{@link org.xtext.example.iptables.iptables.FilterSpec#getFlags <em>Flags</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference list '<em>Flags</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getFlags()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_Flags();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.FilterSpec#getTarget <em>Target</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Target</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getTarget()
   * @see #getFilterSpec()
   * @generated
   */
  EAttribute getFilterSpec_Target();

  /**
   * Returns the meta object for the containment reference '{@link org.xtext.example.iptables.iptables.FilterSpec#getLp <em>Lp</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the containment reference '<em>Lp</em>'.
   * @see org.xtext.example.iptables.iptables.FilterSpec#getLp()
   * @see #getFilterSpec()
   * @generated
   */
  EReference getFilterSpec_Lp();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.Interface <em>Interface</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Interface</em>'.
   * @see org.xtext.example.iptables.iptables.Interface
   * @generated
   */
  EClass getInterface();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.Interface#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.Interface#getName()
   * @see #getInterface()
   * @generated
   */
  EAttribute getInterface_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.LP <em>LP</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>LP</em>'.
   * @see org.xtext.example.iptables.iptables.LP
   * @generated
   */
  EClass getLP();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.LP#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.LP#getName()
   * @see #getLP()
   * @generated
   */
  EAttribute getLP_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.Match <em>Match</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Match</em>'.
   * @see org.xtext.example.iptables.iptables.Match
   * @generated
   */
  EClass getMatch();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.Match#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.Match#getName()
   * @see #getMatch()
   * @generated
   */
  EAttribute getMatch_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.State <em>State</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>State</em>'.
   * @see org.xtext.example.iptables.iptables.State
   * @generated
   */
  EClass getState();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.State#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.State#getName()
   * @see #getState()
   * @generated
   */
  EAttribute getState_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.TCPFlag <em>TCP Flag</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>TCP Flag</em>'.
   * @see org.xtext.example.iptables.iptables.TCPFlag
   * @generated
   */
  EClass getTCPFlag();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.TCPFlag#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.TCPFlag#getName()
   * @see #getTCPFlag()
   * @generated
   */
  EAttribute getTCPFlag_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.Chain <em>Chain</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Chain</em>'.
   * @see org.xtext.example.iptables.iptables.Chain
   * @generated
   */
  EClass getChain();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.Chain#getChainName <em>Chain Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Chain Name</em>'.
   * @see org.xtext.example.iptables.iptables.Chain#getChainName()
   * @see #getChain()
   * @generated
   */
  EAttribute getChain_ChainName();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.CustomChain <em>Custom Chain</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Custom Chain</em>'.
   * @see org.xtext.example.iptables.iptables.CustomChain
   * @generated
   */
  EClass getCustomChain();

  /**
   * Returns the meta object for the reference '{@link org.xtext.example.iptables.iptables.CustomChain#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the reference '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.CustomChain#getName()
   * @see #getCustomChain()
   * @generated
   */
  EReference getCustomChain_Name();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.ChainDeclaration <em>Chain Declaration</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Chain Declaration</em>'.
   * @see org.xtext.example.iptables.iptables.ChainDeclaration
   * @generated
   */
  EClass getChainDeclaration();

  /**
   * Returns the meta object for class '{@link org.xtext.example.iptables.iptables.ChainName <em>Chain Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for class '<em>Chain Name</em>'.
   * @see org.xtext.example.iptables.iptables.ChainName
   * @generated
   */
  EClass getChainName();

  /**
   * Returns the meta object for the attribute '{@link org.xtext.example.iptables.iptables.ChainName#getName <em>Name</em>}'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the meta object for the attribute '<em>Name</em>'.
   * @see org.xtext.example.iptables.iptables.ChainName#getName()
   * @see #getChainName()
   * @generated
   */
  EAttribute getChainName_Name();

  /**
   * Returns the factory that creates the instances of the model.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the factory that creates the instances of the model.
   * @generated
   */
  IptablesFactory getIptablesFactory();

  /**
   * <!-- begin-user-doc -->
   * Defines literals for the meta objects that represent
   * <ul>
   *   <li>each class,</li>
   *   <li>each feature of each class,</li>
   *   <li>each enum,</li>
   *   <li>and each data type</li>
   * </ul>
   * <!-- end-user-doc -->
   * @generated
   */
  interface Literals
  {
    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.ModelImpl <em>Model</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.ModelImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getModel()
     * @generated
     */
    EClass MODEL = eINSTANCE.getModel();

    /**
     * The meta object literal for the '<em><b>Rules</b></em>' containment reference list feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference MODEL__RULES = eINSTANCE.getModel_Rules();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.RuleImpl <em>Rule</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.RuleImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getRule()
     * @generated
     */
    EClass RULE = eINSTANCE.getRule();

    /**
     * The meta object literal for the '<em><b>Declaration</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference RULE__DECLARATION = eINSTANCE.getRule_Declaration();

    /**
     * The meta object literal for the '<em><b>Filter</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference RULE__FILTER = eINSTANCE.getRule_Filter();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.FilterDeclarationImpl <em>Filter Declaration</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.FilterDeclarationImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilterDeclaration()
     * @generated
     */
    EClass FILTER_DECLARATION = eINSTANCE.getFilterDeclaration();

    /**
     * The meta object literal for the '<em><b>Filter</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_DECLARATION__FILTER = eINSTANCE.getFilterDeclaration_Filter();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.FilteringSpecImpl <em>Filtering Spec</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.FilteringSpecImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilteringSpec()
     * @generated
     */
    EClass FILTERING_SPEC = eINSTANCE.getFilteringSpec();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl <em>Filter Spec</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.FilterSpecImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getFilterSpec()
     * @generated
     */
    EClass FILTER_SPEC = eINSTANCE.getFilterSpec();

    /**
     * The meta object literal for the '<em><b>Option</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__OPTION = eINSTANCE.getFilterSpec_Option();

    /**
     * The meta object literal for the '<em><b>Chain</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__CHAIN = eINSTANCE.getFilterSpec_Chain();

    /**
     * The meta object literal for the '<em><b>Protocol</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__PROTOCOL = eINSTANCE.getFilterSpec_Protocol();

    /**
     * The meta object literal for the '<em><b>Ip</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__IP = eINSTANCE.getFilterSpec_Ip();

    /**
     * The meta object literal for the '<em><b>Interface</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__INTERFACE = eINSTANCE.getFilterSpec_Interface();

    /**
     * The meta object literal for the '<em><b>Ip Dst</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__IP_DST = eINSTANCE.getFilterSpec_IpDst();

    /**
     * The meta object literal for the '<em><b>Source Port</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__SOURCE_PORT = eINSTANCE.getFilterSpec_SourcePort();

    /**
     * The meta object literal for the '<em><b>Destination Port</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__DESTINATION_PORT = eINSTANCE.getFilterSpec_DestinationPort();

    /**
     * The meta object literal for the '<em><b>Neg</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__NEG = eINSTANCE.getFilterSpec_Neg();

    /**
     * The meta object literal for the '<em><b>Syn</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__SYN = eINSTANCE.getFilterSpec_Syn();

    /**
     * The meta object literal for the '<em><b>Matches</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__MATCHES = eINSTANCE.getFilterSpec_Matches();

    /**
     * The meta object literal for the '<em><b>States</b></em>' containment reference list feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__STATES = eINSTANCE.getFilterSpec_States();

    /**
     * The meta object literal for the '<em><b>Dir</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__DIR = eINSTANCE.getFilterSpec_Dir();

    /**
     * The meta object literal for the '<em><b>Status</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__STATUS = eINSTANCE.getFilterSpec_Status();

    /**
     * The meta object literal for the '<em><b>Exam Flags</b></em>' containment reference list feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__EXAM_FLAGS = eINSTANCE.getFilterSpec_ExamFlags();

    /**
     * The meta object literal for the '<em><b>Flags</b></em>' containment reference list feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__FLAGS = eINSTANCE.getFilterSpec_Flags();

    /**
     * The meta object literal for the '<em><b>Target</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute FILTER_SPEC__TARGET = eINSTANCE.getFilterSpec_Target();

    /**
     * The meta object literal for the '<em><b>Lp</b></em>' containment reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference FILTER_SPEC__LP = eINSTANCE.getFilterSpec_Lp();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.InterfaceImpl <em>Interface</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.InterfaceImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getInterface()
     * @generated
     */
    EClass INTERFACE = eINSTANCE.getInterface();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute INTERFACE__NAME = eINSTANCE.getInterface_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.LPImpl <em>LP</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.LPImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getLP()
     * @generated
     */
    EClass LP = eINSTANCE.getLP();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute LP__NAME = eINSTANCE.getLP_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.MatchImpl <em>Match</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.MatchImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getMatch()
     * @generated
     */
    EClass MATCH = eINSTANCE.getMatch();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute MATCH__NAME = eINSTANCE.getMatch_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.StateImpl <em>State</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.StateImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getState()
     * @generated
     */
    EClass STATE = eINSTANCE.getState();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute STATE__NAME = eINSTANCE.getState_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.TCPFlagImpl <em>TCP Flag</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.TCPFlagImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getTCPFlag()
     * @generated
     */
    EClass TCP_FLAG = eINSTANCE.getTCPFlag();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute TCP_FLAG__NAME = eINSTANCE.getTCPFlag_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.ChainImpl <em>Chain</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.ChainImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChain()
     * @generated
     */
    EClass CHAIN = eINSTANCE.getChain();

    /**
     * The meta object literal for the '<em><b>Chain Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute CHAIN__CHAIN_NAME = eINSTANCE.getChain_ChainName();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.CustomChainImpl <em>Custom Chain</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.CustomChainImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getCustomChain()
     * @generated
     */
    EClass CUSTOM_CHAIN = eINSTANCE.getCustomChain();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' reference feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EReference CUSTOM_CHAIN__NAME = eINSTANCE.getCustomChain_Name();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.ChainDeclarationImpl <em>Chain Declaration</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.ChainDeclarationImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChainDeclaration()
     * @generated
     */
    EClass CHAIN_DECLARATION = eINSTANCE.getChainDeclaration();

    /**
     * The meta object literal for the '{@link org.xtext.example.iptables.iptables.impl.ChainNameImpl <em>Chain Name</em>}' class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see org.xtext.example.iptables.iptables.impl.ChainNameImpl
     * @see org.xtext.example.iptables.iptables.impl.IptablesPackageImpl#getChainName()
     * @generated
     */
    EClass CHAIN_NAME = eINSTANCE.getChainName();

    /**
     * The meta object literal for the '<em><b>Name</b></em>' attribute feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    EAttribute CHAIN_NAME__NAME = eINSTANCE.getChainName_Name();

  }

} //IptablesPackage
