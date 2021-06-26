/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EObject;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Rule</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.Rule#getDeclaration <em>Declaration</em>}</li>
 *   <li>{@link org.xtext.example.iptables.iptables.Rule#getFilter <em>Filter</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.xtext.example.iptables.iptables.IptablesPackage#getRule()
 * @model
 * @generated
 */
public interface Rule extends EObject
{
  /**
   * Returns the value of the '<em><b>Declaration</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Declaration</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Declaration</em>' containment reference.
   * @see #setDeclaration(ChainDeclaration)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getRule_Declaration()
   * @model containment="true"
   * @generated
   */
  ChainDeclaration getDeclaration();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.Rule#getDeclaration <em>Declaration</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Declaration</em>' containment reference.
   * @see #getDeclaration()
   * @generated
   */
  void setDeclaration(ChainDeclaration value);

  /**
   * Returns the value of the '<em><b>Filter</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Filter</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Filter</em>' containment reference.
   * @see #setFilter(FilterDeclaration)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getRule_Filter()
   * @model containment="true"
   * @generated
   */
  FilterDeclaration getFilter();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.Rule#getFilter <em>Filter</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Filter</em>' containment reference.
   * @see #getFilter()
   * @generated
   */
  void setFilter(FilterDeclaration value);

} // Rule
