/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables.impl;

import java.util.Collection;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

import org.xtext.example.iptables.iptables.Chain;
import org.xtext.example.iptables.iptables.FilterSpec;
import org.xtext.example.iptables.iptables.Interface;
import org.xtext.example.iptables.iptables.IptablesPackage;
import org.xtext.example.iptables.iptables.LP;
import org.xtext.example.iptables.iptables.Match;
import org.xtext.example.iptables.iptables.State;
import org.xtext.example.iptables.iptables.TCPFlag;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Filter Spec</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getOption <em>Option</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getChain <em>Chain</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getProtocol <em>Protocol</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getIp <em>Ip</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getInterface <em>Interface</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getIpDst <em>Ip Dst</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getSourcePort <em>Source Port</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getDestinationPort <em>Destination Port</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#isNeg <em>Neg</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#isSyn <em>Syn</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getMatches <em>Matches</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getStates <em>States</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getDir <em>Dir</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getStatus <em>Status</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getExamFlags <em>Exam Flags</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getFlags <em>Flags</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getTarget <em>Target</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.FilterSpecImpl#getLp <em>Lp</em>}</li>
 * </ul>
 * </p>
 *
 * @generated
 */
public class FilterSpecImpl extends FilteringSpecImpl implements FilterSpec
{
  /**
   * The default value of the '{@link #getOption() <em>Option</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getOption()
   * @generated
   * @ordered
   */
  protected static final String OPTION_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getOption() <em>Option</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getOption()
   * @generated
   * @ordered
   */
  protected String option = OPTION_EDEFAULT;

  /**
   * The cached value of the '{@link #getChain() <em>Chain</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getChain()
   * @generated
   * @ordered
   */
  protected Chain chain;

  /**
   * The default value of the '{@link #getProtocol() <em>Protocol</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getProtocol()
   * @generated
   * @ordered
   */
  protected static final String PROTOCOL_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getProtocol() <em>Protocol</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getProtocol()
   * @generated
   * @ordered
   */
  protected String protocol = PROTOCOL_EDEFAULT;

  /**
   * The default value of the '{@link #getIp() <em>Ip</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getIp()
   * @generated
   * @ordered
   */
  protected static final String IP_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getIp() <em>Ip</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getIp()
   * @generated
   * @ordered
   */
  protected String ip = IP_EDEFAULT;

  /**
   * The cached value of the '{@link #getInterface() <em>Interface</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getInterface()
   * @generated
   * @ordered
   */
  protected Interface interface_;

  /**
   * The default value of the '{@link #getIpDst() <em>Ip Dst</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getIpDst()
   * @generated
   * @ordered
   */
  protected static final String IP_DST_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getIpDst() <em>Ip Dst</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getIpDst()
   * @generated
   * @ordered
   */
  protected String ipDst = IP_DST_EDEFAULT;

  /**
   * The default value of the '{@link #getSourcePort() <em>Source Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getSourcePort()
   * @generated
   * @ordered
   */
  protected static final int SOURCE_PORT_EDEFAULT = 0;

  /**
   * The cached value of the '{@link #getSourcePort() <em>Source Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getSourcePort()
   * @generated
   * @ordered
   */
  protected int sourcePort = SOURCE_PORT_EDEFAULT;

  /**
   * The default value of the '{@link #getDestinationPort() <em>Destination Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getDestinationPort()
   * @generated
   * @ordered
   */
  protected static final int DESTINATION_PORT_EDEFAULT = 0;

  /**
   * The cached value of the '{@link #getDestinationPort() <em>Destination Port</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getDestinationPort()
   * @generated
   * @ordered
   */
  protected int destinationPort = DESTINATION_PORT_EDEFAULT;

  /**
   * The default value of the '{@link #isNeg() <em>Neg</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #isNeg()
   * @generated
   * @ordered
   */
  protected static final boolean NEG_EDEFAULT = false;

  /**
   * The cached value of the '{@link #isNeg() <em>Neg</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #isNeg()
   * @generated
   * @ordered
   */
  protected boolean neg = NEG_EDEFAULT;

  /**
   * The default value of the '{@link #isSyn() <em>Syn</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #isSyn()
   * @generated
   * @ordered
   */
  protected static final boolean SYN_EDEFAULT = false;

  /**
   * The cached value of the '{@link #isSyn() <em>Syn</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #isSyn()
   * @generated
   * @ordered
   */
  protected boolean syn = SYN_EDEFAULT;

  /**
   * The cached value of the '{@link #getMatches() <em>Matches</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getMatches()
   * @generated
   * @ordered
   */
  protected Match matches;

  /**
   * The cached value of the '{@link #getStates() <em>States</em>}' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getStates()
   * @generated
   * @ordered
   */
  protected EList<State> states;

  /**
   * The default value of the '{@link #getDir() <em>Dir</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getDir()
   * @generated
   * @ordered
   */
  protected static final String DIR_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getDir() <em>Dir</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getDir()
   * @generated
   * @ordered
   */
  protected String dir = DIR_EDEFAULT;

  /**
   * The default value of the '{@link #getStatus() <em>Status</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getStatus()
   * @generated
   * @ordered
   */
  protected static final String STATUS_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getStatus() <em>Status</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getStatus()
   * @generated
   * @ordered
   */
  protected String status = STATUS_EDEFAULT;

  /**
   * The cached value of the '{@link #getExamFlags() <em>Exam Flags</em>}' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getExamFlags()
   * @generated
   * @ordered
   */
  protected EList<TCPFlag> examFlags;

  /**
   * The cached value of the '{@link #getFlags() <em>Flags</em>}' containment reference list.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getFlags()
   * @generated
   * @ordered
   */
  protected EList<TCPFlag> flags;

  /**
   * The default value of the '{@link #getTarget() <em>Target</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getTarget()
   * @generated
   * @ordered
   */
  protected static final String TARGET_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getTarget() <em>Target</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getTarget()
   * @generated
   * @ordered
   */
  protected String target = TARGET_EDEFAULT;

  /**
   * The cached value of the '{@link #getLp() <em>Lp</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getLp()
   * @generated
   * @ordered
   */
  protected LP lp;

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  protected FilterSpecImpl()
  {
    super();
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  protected EClass eStaticClass()
  {
    return IptablesPackage.Literals.FILTER_SPEC;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getOption()
  {
    return option;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setOption(String newOption)
  {
    String oldOption = option;
    option = newOption;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__OPTION, oldOption, option));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Chain getChain()
  {
    return chain;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public NotificationChain basicSetChain(Chain newChain, NotificationChain msgs)
  {
    Chain oldChain = chain;
    chain = newChain;
    if (eNotificationRequired())
    {
      ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__CHAIN, oldChain, newChain);
      if (msgs == null) msgs = notification; else msgs.add(notification);
    }
    return msgs;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setChain(Chain newChain)
  {
    if (newChain != chain)
    {
      NotificationChain msgs = null;
      if (chain != null)
        msgs = ((InternalEObject)chain).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__CHAIN, null, msgs);
      if (newChain != null)
        msgs = ((InternalEObject)newChain).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__CHAIN, null, msgs);
      msgs = basicSetChain(newChain, msgs);
      if (msgs != null) msgs.dispatch();
    }
    else if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__CHAIN, newChain, newChain));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getProtocol()
  {
    return protocol;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setProtocol(String newProtocol)
  {
    String oldProtocol = protocol;
    protocol = newProtocol;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__PROTOCOL, oldProtocol, protocol));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getIp()
  {
    return ip;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setIp(String newIp)
  {
    String oldIp = ip;
    ip = newIp;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__IP, oldIp, ip));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Interface getInterface()
  {
    return interface_;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public NotificationChain basicSetInterface(Interface newInterface, NotificationChain msgs)
  {
    Interface oldInterface = interface_;
    interface_ = newInterface;
    if (eNotificationRequired())
    {
      ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__INTERFACE, oldInterface, newInterface);
      if (msgs == null) msgs = notification; else msgs.add(notification);
    }
    return msgs;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setInterface(Interface newInterface)
  {
    if (newInterface != interface_)
    {
      NotificationChain msgs = null;
      if (interface_ != null)
        msgs = ((InternalEObject)interface_).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__INTERFACE, null, msgs);
      if (newInterface != null)
        msgs = ((InternalEObject)newInterface).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__INTERFACE, null, msgs);
      msgs = basicSetInterface(newInterface, msgs);
      if (msgs != null) msgs.dispatch();
    }
    else if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__INTERFACE, newInterface, newInterface));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getIpDst()
  {
    return ipDst;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setIpDst(String newIpDst)
  {
    String oldIpDst = ipDst;
    ipDst = newIpDst;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__IP_DST, oldIpDst, ipDst));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public int getSourcePort()
  {
    return sourcePort;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setSourcePort(int newSourcePort)
  {
    int oldSourcePort = sourcePort;
    sourcePort = newSourcePort;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__SOURCE_PORT, oldSourcePort, sourcePort));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public int getDestinationPort()
  {
    return destinationPort;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setDestinationPort(int newDestinationPort)
  {
    int oldDestinationPort = destinationPort;
    destinationPort = newDestinationPort;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__DESTINATION_PORT, oldDestinationPort, destinationPort));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public boolean isNeg()
  {
    return neg;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setNeg(boolean newNeg)
  {
    boolean oldNeg = neg;
    neg = newNeg;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__NEG, oldNeg, neg));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public boolean isSyn()
  {
    return syn;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setSyn(boolean newSyn)
  {
    boolean oldSyn = syn;
    syn = newSyn;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__SYN, oldSyn, syn));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public Match getMatches()
  {
    return matches;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public NotificationChain basicSetMatches(Match newMatches, NotificationChain msgs)
  {
    Match oldMatches = matches;
    matches = newMatches;
    if (eNotificationRequired())
    {
      ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__MATCHES, oldMatches, newMatches);
      if (msgs == null) msgs = notification; else msgs.add(notification);
    }
    return msgs;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setMatches(Match newMatches)
  {
    if (newMatches != matches)
    {
      NotificationChain msgs = null;
      if (matches != null)
        msgs = ((InternalEObject)matches).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__MATCHES, null, msgs);
      if (newMatches != null)
        msgs = ((InternalEObject)newMatches).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__MATCHES, null, msgs);
      msgs = basicSetMatches(newMatches, msgs);
      if (msgs != null) msgs.dispatch();
    }
    else if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__MATCHES, newMatches, newMatches));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public EList<State> getStates()
  {
    if (states == null)
    {
      states = new EObjectContainmentEList<State>(State.class, this, IptablesPackage.FILTER_SPEC__STATES);
    }
    return states;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getDir()
  {
    return dir;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setDir(String newDir)
  {
    String oldDir = dir;
    dir = newDir;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__DIR, oldDir, dir));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getStatus()
  {
    return status;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setStatus(String newStatus)
  {
    String oldStatus = status;
    status = newStatus;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__STATUS, oldStatus, status));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public EList<TCPFlag> getExamFlags()
  {
    if (examFlags == null)
    {
      examFlags = new EObjectContainmentEList<TCPFlag>(TCPFlag.class, this, IptablesPackage.FILTER_SPEC__EXAM_FLAGS);
    }
    return examFlags;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public EList<TCPFlag> getFlags()
  {
    if (flags == null)
    {
      flags = new EObjectContainmentEList<TCPFlag>(TCPFlag.class, this, IptablesPackage.FILTER_SPEC__FLAGS);
    }
    return flags;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getTarget()
  {
    return target;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setTarget(String newTarget)
  {
    String oldTarget = target;
    target = newTarget;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__TARGET, oldTarget, target));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public LP getLp()
  {
    return lp;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public NotificationChain basicSetLp(LP newLp, NotificationChain msgs)
  {
    LP oldLp = lp;
    lp = newLp;
    if (eNotificationRequired())
    {
      ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__LP, oldLp, newLp);
      if (msgs == null) msgs = notification; else msgs.add(notification);
    }
    return msgs;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setLp(LP newLp)
  {
    if (newLp != lp)
    {
      NotificationChain msgs = null;
      if (lp != null)
        msgs = ((InternalEObject)lp).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__LP, null, msgs);
      if (newLp != null)
        msgs = ((InternalEObject)newLp).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - IptablesPackage.FILTER_SPEC__LP, null, msgs);
      msgs = basicSetLp(newLp, msgs);
      if (msgs != null) msgs.dispatch();
    }
    else if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.FILTER_SPEC__LP, newLp, newLp));
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs)
  {
    switch (featureID)
    {
      case IptablesPackage.FILTER_SPEC__CHAIN:
        return basicSetChain(null, msgs);
      case IptablesPackage.FILTER_SPEC__INTERFACE:
        return basicSetInterface(null, msgs);
      case IptablesPackage.FILTER_SPEC__MATCHES:
        return basicSetMatches(null, msgs);
      case IptablesPackage.FILTER_SPEC__STATES:
        return ((InternalEList<?>)getStates()).basicRemove(otherEnd, msgs);
      case IptablesPackage.FILTER_SPEC__EXAM_FLAGS:
        return ((InternalEList<?>)getExamFlags()).basicRemove(otherEnd, msgs);
      case IptablesPackage.FILTER_SPEC__FLAGS:
        return ((InternalEList<?>)getFlags()).basicRemove(otherEnd, msgs);
      case IptablesPackage.FILTER_SPEC__LP:
        return basicSetLp(null, msgs);
    }
    return super.eInverseRemove(otherEnd, featureID, msgs);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public Object eGet(int featureID, boolean resolve, boolean coreType)
  {
    switch (featureID)
    {
      case IptablesPackage.FILTER_SPEC__OPTION:
        return getOption();
      case IptablesPackage.FILTER_SPEC__CHAIN:
        return getChain();
      case IptablesPackage.FILTER_SPEC__PROTOCOL:
        return getProtocol();
      case IptablesPackage.FILTER_SPEC__IP:
        return getIp();
      case IptablesPackage.FILTER_SPEC__INTERFACE:
        return getInterface();
      case IptablesPackage.FILTER_SPEC__IP_DST:
        return getIpDst();
      case IptablesPackage.FILTER_SPEC__SOURCE_PORT:
        return getSourcePort();
      case IptablesPackage.FILTER_SPEC__DESTINATION_PORT:
        return getDestinationPort();
      case IptablesPackage.FILTER_SPEC__NEG:
        return isNeg();
      case IptablesPackage.FILTER_SPEC__SYN:
        return isSyn();
      case IptablesPackage.FILTER_SPEC__MATCHES:
        return getMatches();
      case IptablesPackage.FILTER_SPEC__STATES:
        return getStates();
      case IptablesPackage.FILTER_SPEC__DIR:
        return getDir();
      case IptablesPackage.FILTER_SPEC__STATUS:
        return getStatus();
      case IptablesPackage.FILTER_SPEC__EXAM_FLAGS:
        return getExamFlags();
      case IptablesPackage.FILTER_SPEC__FLAGS:
        return getFlags();
      case IptablesPackage.FILTER_SPEC__TARGET:
        return getTarget();
      case IptablesPackage.FILTER_SPEC__LP:
        return getLp();
    }
    return super.eGet(featureID, resolve, coreType);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @SuppressWarnings("unchecked")
  @Override
  public void eSet(int featureID, Object newValue)
  {
    switch (featureID)
    {
      case IptablesPackage.FILTER_SPEC__OPTION:
        setOption((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__CHAIN:
        setChain((Chain)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__PROTOCOL:
        setProtocol((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__IP:
        setIp((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__INTERFACE:
        setInterface((Interface)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__IP_DST:
        setIpDst((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__SOURCE_PORT:
        setSourcePort((Integer)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__DESTINATION_PORT:
        setDestinationPort((Integer)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__NEG:
        setNeg((Boolean)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__SYN:
        setSyn((Boolean)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__MATCHES:
        setMatches((Match)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__STATES:
        getStates().clear();
        getStates().addAll((Collection<? extends State>)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__DIR:
        setDir((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__STATUS:
        setStatus((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__EXAM_FLAGS:
        getExamFlags().clear();
        getExamFlags().addAll((Collection<? extends TCPFlag>)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__FLAGS:
        getFlags().clear();
        getFlags().addAll((Collection<? extends TCPFlag>)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__TARGET:
        setTarget((String)newValue);
        return;
      case IptablesPackage.FILTER_SPEC__LP:
        setLp((LP)newValue);
        return;
    }
    super.eSet(featureID, newValue);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public void eUnset(int featureID)
  {
    switch (featureID)
    {
      case IptablesPackage.FILTER_SPEC__OPTION:
        setOption(OPTION_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__CHAIN:
        setChain((Chain)null);
        return;
      case IptablesPackage.FILTER_SPEC__PROTOCOL:
        setProtocol(PROTOCOL_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__IP:
        setIp(IP_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__INTERFACE:
        setInterface((Interface)null);
        return;
      case IptablesPackage.FILTER_SPEC__IP_DST:
        setIpDst(IP_DST_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__SOURCE_PORT:
        setSourcePort(SOURCE_PORT_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__DESTINATION_PORT:
        setDestinationPort(DESTINATION_PORT_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__NEG:
        setNeg(NEG_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__SYN:
        setSyn(SYN_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__MATCHES:
        setMatches((Match)null);
        return;
      case IptablesPackage.FILTER_SPEC__STATES:
        getStates().clear();
        return;
      case IptablesPackage.FILTER_SPEC__DIR:
        setDir(DIR_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__STATUS:
        setStatus(STATUS_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__EXAM_FLAGS:
        getExamFlags().clear();
        return;
      case IptablesPackage.FILTER_SPEC__FLAGS:
        getFlags().clear();
        return;
      case IptablesPackage.FILTER_SPEC__TARGET:
        setTarget(TARGET_EDEFAULT);
        return;
      case IptablesPackage.FILTER_SPEC__LP:
        setLp((LP)null);
        return;
    }
    super.eUnset(featureID);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public boolean eIsSet(int featureID)
  {
    switch (featureID)
    {
      case IptablesPackage.FILTER_SPEC__OPTION:
        return OPTION_EDEFAULT == null ? option != null : !OPTION_EDEFAULT.equals(option);
      case IptablesPackage.FILTER_SPEC__CHAIN:
        return chain != null;
      case IptablesPackage.FILTER_SPEC__PROTOCOL:
        return PROTOCOL_EDEFAULT == null ? protocol != null : !PROTOCOL_EDEFAULT.equals(protocol);
      case IptablesPackage.FILTER_SPEC__IP:
        return IP_EDEFAULT == null ? ip != null : !IP_EDEFAULT.equals(ip);
      case IptablesPackage.FILTER_SPEC__INTERFACE:
        return interface_ != null;
      case IptablesPackage.FILTER_SPEC__IP_DST:
        return IP_DST_EDEFAULT == null ? ipDst != null : !IP_DST_EDEFAULT.equals(ipDst);
      case IptablesPackage.FILTER_SPEC__SOURCE_PORT:
        return sourcePort != SOURCE_PORT_EDEFAULT;
      case IptablesPackage.FILTER_SPEC__DESTINATION_PORT:
        return destinationPort != DESTINATION_PORT_EDEFAULT;
      case IptablesPackage.FILTER_SPEC__NEG:
        return neg != NEG_EDEFAULT;
      case IptablesPackage.FILTER_SPEC__SYN:
        return syn != SYN_EDEFAULT;
      case IptablesPackage.FILTER_SPEC__MATCHES:
        return matches != null;
      case IptablesPackage.FILTER_SPEC__STATES:
        return states != null && !states.isEmpty();
      case IptablesPackage.FILTER_SPEC__DIR:
        return DIR_EDEFAULT == null ? dir != null : !DIR_EDEFAULT.equals(dir);
      case IptablesPackage.FILTER_SPEC__STATUS:
        return STATUS_EDEFAULT == null ? status != null : !STATUS_EDEFAULT.equals(status);
      case IptablesPackage.FILTER_SPEC__EXAM_FLAGS:
        return examFlags != null && !examFlags.isEmpty();
      case IptablesPackage.FILTER_SPEC__FLAGS:
        return flags != null && !flags.isEmpty();
      case IptablesPackage.FILTER_SPEC__TARGET:
        return TARGET_EDEFAULT == null ? target != null : !TARGET_EDEFAULT.equals(target);
      case IptablesPackage.FILTER_SPEC__LP:
        return lp != null;
    }
    return super.eIsSet(featureID);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public String toString()
  {
    if (eIsProxy()) return super.toString();

    StringBuffer result = new StringBuffer(super.toString());
    result.append(" (option: ");
    result.append(option);
    result.append(", protocol: ");
    result.append(protocol);
    result.append(", ip: ");
    result.append(ip);
    result.append(", ipDst: ");
    result.append(ipDst);
    result.append(", sourcePort: ");
    result.append(sourcePort);
    result.append(", destinationPort: ");
    result.append(destinationPort);
    result.append(", neg: ");
    result.append(neg);
    result.append(", syn: ");
    result.append(syn);
    result.append(", dir: ");
    result.append(dir);
    result.append(", status: ");
    result.append(status);
    result.append(", target: ");
    result.append(target);
    result.append(')');
    return result.toString();
  }

} //FilterSpecImpl
