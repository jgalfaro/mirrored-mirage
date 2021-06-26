/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.common.util.EList;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Filter Spec</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getOption <em>Option</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getChain <em>Chain</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getProtocol <em>Protocol</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getIp <em>Ip</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getInterface <em>Interface</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getIpDst <em>Ip Dst</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getSourcePort <em>Source Port</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getDestinationPort <em>Destination Port</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#isNeg <em>Neg</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#isSyn <em>Syn</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getMatches <em>Matches</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getStates <em>States</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getDir <em>Dir</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getStatus <em>Status</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getExamFlags <em>Exam Flags</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getFlags <em>Flags</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getTarget <em>Target</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterSpec#getLp <em>Lp</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec()
 * @model
 * @generated
 */
public interface FilterSpec extends FilteringSpec
{
  /**
   * Returns the value of the '<em><b>Option</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Option</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Option</em>' attribute.
   * @see #setOption(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Option()
   * @model
   * @generated
   */
  String getOption();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getOption <em>Option</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Option</em>' attribute.
   * @see #getOption()
   * @generated
   */
  void setOption(String value);

  /**
   * Returns the value of the '<em><b>Chain</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Chain</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Chain</em>' containment reference.
   * @see #setChain(Chain)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Chain()
   * @model containment="true"
   * @generated
   */
  Chain getChain();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getChain <em>Chain</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Chain</em>' containment reference.
   * @see #getChain()
   * @generated
   */
  void setChain(Chain value);

  /**
   * Returns the value of the '<em><b>Protocol</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Protocol</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Protocol</em>' attribute.
   * @see #setProtocol(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Protocol()
   * @model
   * @generated
   */
  String getProtocol();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getProtocol <em>Protocol</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Protocol</em>' attribute.
   * @see #getProtocol()
   * @generated
   */
  void setProtocol(String value);

  /**
   * Returns the value of the '<em><b>Ip</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Ip</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Ip</em>' attribute.
   * @see #setIp(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Ip()
   * @model
   * @generated
   */
  String getIp();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getIp <em>Ip</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Ip</em>' attribute.
   * @see #getIp()
   * @generated
   */
  void setIp(String value);

  /**
   * Returns the value of the '<em><b>Interface</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Interface</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Interface</em>' containment reference.
   * @see #setInterface(Interface)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Interface()
   * @model containment="true"
   * @generated
   */
  Interface getInterface();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getInterface <em>Interface</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Interface</em>' containment reference.
   * @see #getInterface()
   * @generated
   */
  void setInterface(Interface value);

  /**
   * Returns the value of the '<em><b>Ip Dst</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Ip Dst</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Ip Dst</em>' attribute.
   * @see #setIpDst(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_IpDst()
   * @model
   * @generated
   */
  String getIpDst();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getIpDst <em>Ip Dst</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Ip Dst</em>' attribute.
   * @see #getIpDst()
   * @generated
   */
  void setIpDst(String value);

  /**
   * Returns the value of the '<em><b>Source Port</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Source Port</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Source Port</em>' attribute.
   * @see #setSourcePort(int)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_SourcePort()
   * @model
   * @generated
   */
  int getSourcePort();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getSourcePort <em>Source Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Source Port</em>' attribute.
   * @see #getSourcePort()
   * @generated
   */
  void setSourcePort(int value);

  /**
   * Returns the value of the '<em><b>Destination Port</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Destination Port</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Destination Port</em>' attribute.
   * @see #setDestinationPort(int)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_DestinationPort()
   * @model
   * @generated
   */
  int getDestinationPort();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getDestinationPort <em>Destination Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Destination Port</em>' attribute.
   * @see #getDestinationPort()
   * @generated
   */
  void setDestinationPort(int value);

  /**
   * Returns the value of the '<em><b>Neg</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Neg</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Neg</em>' attribute.
   * @see #setNeg(boolean)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Neg()
   * @model
   * @generated
   */
  boolean isNeg();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#isNeg <em>Neg</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Neg</em>' attribute.
   * @see #isNeg()
   * @generated
   */
  void setNeg(boolean value);

  /**
   * Returns the value of the '<em><b>Syn</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Syn</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Syn</em>' attribute.
   * @see #setSyn(boolean)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Syn()
   * @model
   * @generated
   */
  boolean isSyn();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#isSyn <em>Syn</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Syn</em>' attribute.
   * @see #isSyn()
   * @generated
   */
  void setSyn(boolean value);

  /**
   * Returns the value of the '<em><b>Matches</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Matches</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Matches</em>' containment reference.
   * @see #setMatches(Match)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Matches()
   * @model containment="true"
   * @generated
   */
  Match getMatches();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getMatches <em>Matches</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Matches</em>' containment reference.
   * @see #getMatches()
   * @generated
   */
  void setMatches(Match value);

  /**
   * Returns the value of the '<em><b>States</b></em>' containment reference list.
   * The list contents are of type {@link org.xtext.example.iptables.iptables.State}.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>States</em>' containment reference list isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>States</em>' containment reference list.
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_States()
   * @model containment="true"
   * @generated
   */
  EList<State> getStates();

  /**
   * Returns the value of the '<em><b>Dir</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Dir</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Dir</em>' attribute.
   * @see #setDir(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Dir()
   * @model
   * @generated
   */
  String getDir();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getDir <em>Dir</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Dir</em>' attribute.
   * @see #getDir()
   * @generated
   */
  void setDir(String value);

  /**
   * Returns the value of the '<em><b>Status</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Status</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Status</em>' attribute.
   * @see #setStatus(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Status()
   * @model
   * @generated
   */
  String getStatus();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getStatus <em>Status</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Status</em>' attribute.
   * @see #getStatus()
   * @generated
   */
  void setStatus(String value);

  /**
   * Returns the value of the '<em><b>Exam Flags</b></em>' containment reference list.
   * The list contents are of type {@link org.xtext.example.iptables.iptables.TCPFlag}.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Exam Flags</em>' containment reference list isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Exam Flags</em>' containment reference list.
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_ExamFlags()
   * @model containment="true"
   * @generated
   */
  EList<TCPFlag> getExamFlags();

  /**
   * Returns the value of the '<em><b>Flags</b></em>' containment reference list.
   * The list contents are of type {@link org.xtext.example.iptables.iptables.TCPFlag}.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Flags</em>' containment reference list isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Flags</em>' containment reference list.
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Flags()
   * @model containment="true"
   * @generated
   */
  EList<TCPFlag> getFlags();

  /**
   * Returns the value of the '<em><b>Target</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Target</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Target</em>' attribute.
   * @see #setTarget(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Target()
   * @model
   * @generated
   */
  String getTarget();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getTarget <em>Target</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Target</em>' attribute.
   * @see #getTarget()
   * @generated
   */
  void setTarget(String value);

  /**
   * Returns the value of the '<em><b>Lp</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Lp</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Lp</em>' containment reference.
   * @see #setLp(LP)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterSpec_Lp()
   * @model containment="true"
   * @generated
   */
  LP getLp();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterSpec#getLp <em>Lp</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Lp</em>' containment reference.
   * @see #getLp()
   * @generated
   */
  void setLp(LP value);

} // FilterSpec
