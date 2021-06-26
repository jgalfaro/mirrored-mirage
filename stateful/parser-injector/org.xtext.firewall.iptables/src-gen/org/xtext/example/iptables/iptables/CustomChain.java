/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EObject;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Custom Chain</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.CustomChain#getName <em>Name</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.xtext.example.iptables.iptables.IptablesPackage#getCustomChain()
 * @model
 * @generated
 */
public interface CustomChain extends EObject
{
  /**
   * Returns the value of the '<em><b>Name</b></em>' reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Name</em>' reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Name</em>' reference.
   * @see #setName(ChainName)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getCustomChain_Name()
   * @model
   * @generated
   */
  ChainName getName();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.CustomChain#getName <em>Name</em>}' reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Name</em>' reference.
   * @see #getName()
   * @generated
   */
  void setName(ChainName value);

} // CustomChain
