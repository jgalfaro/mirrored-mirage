/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables.impl;

import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.ecore.EClass;

import org.eclipse.emf.ecore.impl.ENotificationImpl;
import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;

import org.xtext.example.iptables.iptables.Chain;
import org.xtext.example.iptables.iptables.IptablesPackage;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Chain</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.impl.ChainImpl#getChainName <em>Chain Name</em>}</li>
 * </ul>
 * </p>
 *
 * @generated
 */
public class ChainImpl extends MinimalEObjectImpl.Container implements Chain
{
  /**
   * The default value of the '{@link #getChainName() <em>Chain Name</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getChainName()
   * @generated
   * @ordered
   */
  protected static final String CHAIN_NAME_EDEFAULT = null;

  /**
   * The cached value of the '{@link #getChainName() <em>Chain Name</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @see #getChainName()
   * @generated
   * @ordered
   */
  protected String chainName = CHAIN_NAME_EDEFAULT;

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  protected ChainImpl()
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
    return IptablesPackage.Literals.CHAIN;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public String getChainName()
  {
    return chainName;
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  public void setChainName(String newChainName)
  {
    String oldChainName = chainName;
    chainName = newChainName;
    if (eNotificationRequired())
      eNotify(new ENotificationImpl(this, Notification.SET, IptablesPackage.CHAIN__CHAIN_NAME, oldChainName, chainName));
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
      case IptablesPackage.CHAIN__CHAIN_NAME:
        return getChainName();
    }
    return super.eGet(featureID, resolve, coreType);
  }

  /**
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  @Override
  public void eSet(int featureID, Object newValue)
  {
    switch (featureID)
    {
      case IptablesPackage.CHAIN__CHAIN_NAME:
        setChainName((String)newValue);
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
      case IptablesPackage.CHAIN__CHAIN_NAME:
        setChainName(CHAIN_NAME_EDEFAULT);
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
      case IptablesPackage.CHAIN__CHAIN_NAME:
        return CHAIN_NAME_EDEFAULT == null ? chainName != null : !CHAIN_NAME_EDEFAULT.equals(chainName);
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
    result.append(" (chainName: ");
    result.append(chainName);
    result.append(')');
    return result.toString();
  }

} //ChainImpl
