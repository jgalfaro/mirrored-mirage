/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EObject;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Chain</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.Chain#getChainName <em>Chain Name</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.xtext.example.iptables.iptables.IptablesPackage#getChain()
 * @model
 * @generated
 */
public interface Chain extends EObject
{
  /**
   * Returns the value of the '<em><b>Chain Name</b></em>' attribute.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Chain Name</em>' attribute isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Chain Name</em>' attribute.
   * @see #setChainName(String)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getChain_ChainName()
   * @model
   * @generated
   */
  String getChainName();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.Chain#getChainName <em>Chain Name</em>}' attribute.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Chain Name</em>' attribute.
   * @see #getChainName()
   * @generated
   */
  void setChainName(String value);

} // Chain
