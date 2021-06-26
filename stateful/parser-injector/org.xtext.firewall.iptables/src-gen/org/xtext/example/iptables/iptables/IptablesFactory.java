/**
 * <copyright>
 * </copyright>
 *
 */
package org.xtext.example.iptables.iptables;

import org.eclipse.emf.ecore.EFactory;

/**
 * <!-- begin-user-doc -->
 * The <b>Factory</b> for the model.
 * It provides a create method for each non-abstract class of the model.
 * <!-- end-user-doc -->
 * @see org.xtext.example.iptables.iptables.IptablesPackage
 * @generated
 */
public interface IptablesFactory extends EFactory
{
  /**
   * The singleton instance of the factory.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @generated
   */
  IptablesFactory eINSTANCE = org.xtext.example.iptables.iptables.impl.IptablesFactoryImpl.init();

  /**
   * Returns a new object of class '<em>Model</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Model</em>'.
   * @generated
   */
  Model createModel();

  /**
   * Returns a new object of class '<em>Rule</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Rule</em>'.
   * @generated
   */
  Rule createRule();

  /**
   * Returns a new object of class '<em>Filter Declaration</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Filter Declaration</em>'.
   * @generated
   */
  FilterDeclaration createFilterDeclaration();

  /**
   * Returns a new object of class '<em>Filtering Spec</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Filtering Spec</em>'.
   * @generated
   */
  FilteringSpec createFilteringSpec();

  /**
   * Returns a new object of class '<em>Filter Spec</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Filter Spec</em>'.
   * @generated
   */
  FilterSpec createFilterSpec();

  /**
   * Returns a new object of class '<em>Interface</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Interface</em>'.
   * @generated
   */
  Interface createInterface();

  /**
   * Returns a new object of class '<em>LP</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>LP</em>'.
   * @generated
   */
  LP createLP();

  /**
   * Returns a new object of class '<em>Match</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Match</em>'.
   * @generated
   */
  Match createMatch();

  /**
   * Returns a new object of class '<em>State</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>State</em>'.
   * @generated
   */
  State createState();

  /**
   * Returns a new object of class '<em>TCP Flag</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>TCP Flag</em>'.
   * @generated
   */
  TCPFlag createTCPFlag();

  /**
   * Returns a new object of class '<em>Chain</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Chain</em>'.
   * @generated
   */
  Chain createChain();

  /**
   * Returns a new object of class '<em>Custom Chain</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Custom Chain</em>'.
   * @generated
   */
  CustomChain createCustomChain();

  /**
   * Returns a new object of class '<em>Chain Declaration</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Chain Declaration</em>'.
   * @generated
   */
  ChainDeclaration createChainDeclaration();

  /**
   * Returns a new object of class '<em>Chain Name</em>'.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return a new object of class '<em>Chain Name</em>'.
   * @generated
   */
  ChainName createChainName();

  /**
   * Returns the package supported by this factory.
   * <!-- begin-user-doc -->
   * <!-- end-user-doc -->
   * @return the package supported by this factory.
   * @generated
   */
  IptablesPackage getIptablesPackage();

} //IptablesFactory
