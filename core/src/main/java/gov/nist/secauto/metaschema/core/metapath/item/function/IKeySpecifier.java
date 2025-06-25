/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;

import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A common interface for all key specifier implementations.
 */
@FunctionalInterface
public interface IKeySpecifier {

  /**
   * Perform a lookup on the provided target item.
   *
   * @param targetItem
   *          the item to query
   * @param dynamicContext
   *          the dynamic context to use for expression evaluation
   * @param focus
   *          the focus item for expression evaluation
   * @return a stream of collection values matching this key specifier
   */
  Stream<? extends ICollectionValue> lookup(
      @NonNull IItem targetItem,
      @NonNull DynamicContext dynamicContext,
      @NonNull ISequence<?> focus);
}
