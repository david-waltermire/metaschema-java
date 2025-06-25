/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AbstractItemType;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An abstract implementation of an atomic type.
 *
 * @param <T>
 *          the Java type of the item supported by the implementation
 */
public abstract class AbstractAtomicOrUnionType<T extends IAnyAtomicItem>
    extends AbstractItemType<T>
    implements IAtomicOrUnionType<T> {
  @NonNull
  private final ICastExecutor<T> castExecutor;

  /**
   * Construct a new atomic type.
   *
   * @param itemClass
   *          the item class this atomic type supports
   * @param castExecutor
   *          the executor used to cast an item to an item of this type
   */
  public AbstractAtomicOrUnionType(
      @NonNull Class<T> itemClass,
      @NonNull ICastExecutor<T> castExecutor) {
    super(itemClass);
    this.castExecutor = castExecutor;
  }

  @Override
  public T cast(IAnyAtomicItem item) {
    return castExecutor.cast(item);
  }

  @Override
  protected String generateSignature() {
    return getQName().toEQName();
  }
}
