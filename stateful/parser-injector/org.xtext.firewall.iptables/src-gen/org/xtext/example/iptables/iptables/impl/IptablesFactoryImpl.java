/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables.impl;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EPackage;

import org.eclipse.emf.ecore.impl.EFactoryImpl;

import org.eclipse.emf.ecore.plugin.EcorePlugin;

import org.xtext.example.iptables.iptables.*;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model <b>Factory</b>.
 * <!-- end-user-doc -->
 * @generated
 */
public class IptablesFactoryImpl extends EFactoryImpl implements IptablesFactory
{
  /**
   * Creates the default factory implementation.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public static IptablesFactory init()
  {
    try
    {
      IptablesFactory theIptablesFactory = (IptablesFactory)EPackage.Registry.INSTANCE.getEFactory("http://www.xtext.org/example/iptables/Iptables"); 
      if (theIptablesFactory != null)
      {
        return theIptablesFactory;
      }
    }
    catch (Exception exception)
    {
      EcorePlugin.INSTANCE.log(exception);
    }
    return new IptablesFactoryImpl();
  }

  /**
   * Creates an instance of the factory.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public IptablesFactoryImpl()
  {
    super();
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public EObject create(EClass eClass)
  {
    switch (eClass.getClassifierID())
    {
      case IptablesPackage.MODEL: return createModel();
      case IptablesPackage.RULE: return createRule();
      case IptablesPackage.FILTER_DECLARATION: return createFilterDeclaration();
      case IptablesPackage.FILTERING_SPEC: return createFilteringSpec();
      case IptablesPackage.FILTER_SPEC: return createFilterSpec();
      case IptablesPackage.INTERFACE: return createInterface();
      case IptablesPackage.LP: return createLP();
      case IptablesPackage.MATCH: return createMatch();
      case IptablesPackage.STATE: return createState();
      case IptablesPackage.TCP_FLAG: return createTCPFlag();
      case IptablesPackage.CHAIN: return createChain();
      case IptablesPackage.CUSTOM_CHAIN: return createCustomChain();
      case IptablesPackage.CHAIN_DECLARATION: return createChainDeclaration();
      case IptablesPackage.CHAIN_NAME: return createChainName();
      default:
        throw new IllegalArgumentException("The class '" + eClass.getName() + "' is not a valid classifier");
    }
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Model createModel()
  {
    ModelImpl model = new ModelImpl();
    return model;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Rule createRule()
  {
    RuleImpl rule = new RuleImpl();
    return rule;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public FilterDeclaration createFilterDeclaration()
  {
    FilterDeclarationImpl filterDeclaration = new FilterDeclarationImpl();
    return filterDeclaration;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public FilteringSpec createFilteringSpec()
  {
    FilteringSpecImpl filteringSpec = new FilteringSpecImpl();
    return filteringSpec;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public FilterSpec createFilterSpec()
  {
    FilterSpecImpl filterSpec = new FilterSpecImpl();
    return filterSpec;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Interface createInterface()
  {
    InterfaceImpl interface_ = new InterfaceImpl();
    return interface_;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public LP createLP()
  {
    LPImpl lp = new LPImpl();
    return lp;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Match createMatch()
  {
    MatchImpl match = new MatchImpl();
    return match;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public State createState()
  {
    StateImpl state = new StateImpl();
    return state;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public TCPFlag createTCPFlag()
  {
    TCPFlagImpl tcpFlag = new TCPFlagImpl();
    return tcpFlag;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Chain createChain()
  {
    ChainImpl chain = new ChainImpl();
    return chain;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public CustomChain createCustomChain()
  {
    CustomChainImpl customChain = new CustomChainImpl();
    return customChain;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public ChainDeclaration createChainDeclaration()
  {
    ChainDeclarationImpl chainDeclaration = new ChainDeclarationImpl();
    return chainDeclaration;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public ChainName createChainName()
  {
    ChainNameImpl chainName = new ChainNameImpl();
    return chainName;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public IptablesPackage getIptablesPackage()
  {
    return (IptablesPackage)getEPackage();
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @deprecated
   * @generated
   */
  @Deprecated
  public static IptablesPackage getPackage()
  {
    return IptablesPackage.eINSTANCE;
  }

} //IptablesFactoryImpl
