/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst.path;

import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;

import java.util.function.Predicate;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A common interface for all wildcard matchers.
 * <p>
 * Based on the XPath 3.1
 * <a href="https://www.w3.org/TR/xpath-31/#node-tests">wildcard node test</a>
 * syntax.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IWildcardMatcher extends Predicate<IDefinitionNodeItem<?, ?>> {
  /**
   * Construct a wildcard matcher that matches the provided local name in any
   * namespace.
   *
   * @param localName
   *          the name used to match nodes
   * @return the matcher
   */
  @NonNull
  static IWildcardMatcher anyNamespace(@NonNull String localName) {
    // the grammar should ensure that localName is not empty
    assert !localName.isEmpty();
    return new MatchAnyNamespace(localName);
  }

  /**
   * Construct a wildcard matcher that matches any local name in the provided
   * namespace.
   *
   * @param namespace
   *          the namespace used to match nodes
   * @return the matcher
   */
  @NonNull
  static IWildcardMatcher anyLocalName(@NonNull String namespace) {
    return new MatchAnyLocalName(namespace);
  }

  @Override
  @NonNull
  String toString();
}
