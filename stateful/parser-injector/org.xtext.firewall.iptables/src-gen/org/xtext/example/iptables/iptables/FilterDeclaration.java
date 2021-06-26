/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EObject;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Filter Declaration</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 *   <li>{@link org.xtext.example.iptables.iptables.FilterDeclaration#getFilter <em>Filter</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterDeclaration()
 * @model
 * @generated
 */
public interface FilterDeclaration extends EObject
{
  /**
   * Returns the value of the '<em><b>Filter</b></em>' containment reference.
   * <!-- begin-user-doc -->
   * <p>
   * If the meaning of the '<em>Filter</em>' containment reference isn't clear,
   * there really should be more of a description here...
   * </p>
   * <!-- end-user-doc -->
   * @return the value of the '<em>Filter</em>' containment reference.
   * @see #setFilter(FilteringSpec)
   * @see org.xtext.example.iptables.iptables.IptablesPackage#getFilterDeclaration_Filter()
   * @model containment="true"
   * @generated
   */
  FilteringSpec getFilter();

  /**
   * Sets the value of the '{@link org.xtext.example.iptables.iptables.FilterDeclaration#getFilter <em>Filter</em>}' containment reference.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @param value the new value of the '<em>Filter</em>' containment reference.
   * @see #getFilter()
   * @generated
   */
  void setFilter(FilteringSpec value);

} // FilterDeclaration
