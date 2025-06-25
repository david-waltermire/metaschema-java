/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An item type that applies to all items of a specific node-based type.
 *
 * @param <T>
 *          the Java type of the function-based item supported by the
 *          implementation
 */
public final class AnyFunctionItemType<T extends IFunction>
    extends AbstractItemType<T> {
  /**
   * Matches to all {@link IFunction}.
   */
  @NonNull
  public static final IItemType ANY_FUNCTION = new AnyFunctionItemType<>(
      IFunction.class,
      "function(*)");

  /**
   * Matches to all {@link IMapItem}.
   */
  @NonNull
  public static final IItemType ANY_MAP = new AnyFunctionItemType<>(
      IMapItem.class,
      "map(*)");
  /**
   * Matches to all {@link IArrayItem}.
   */
  @NonNull
  public static final IItemType ANY_ARRAY = new AnyFunctionItemType<>(
      IArrayItem.class,
      "array(*)");

  @NonNull
  private final String signatureBase;

  private AnyFunctionItemType(
      @NonNull Class<T> itemClass,
      @NonNull String signature) {
    super(itemClass);
    this.signatureBase = signature;
  }

  @Override
  protected String generateSignature() {
    return signatureBase;
  }
}
