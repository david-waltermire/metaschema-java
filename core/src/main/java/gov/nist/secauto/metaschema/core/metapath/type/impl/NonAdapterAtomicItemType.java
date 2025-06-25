/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.AbstractAtomicOrUnionType;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An abstract implementation of an abstract atomic type.
 *
 * @param <T>
 *          the Java type of the item supported by the implementation
 */
public class NonAdapterAtomicItemType<T extends IAnyAtomicItem>
    extends AbstractAtomicOrUnionType<T> {
  @NonNull
  private final IEnhancedQName qname;

  /**
   * Construct a new atomic type.
   *
   * @param itemClass
   *          the item class this atomic type supports
   * @param castExecutor
   *          the executor used to cast an item to an item of this type
   * @param qname
   *          the qualified name of the data type
   */
  public NonAdapterAtomicItemType(
      @NonNull Class<T> itemClass,
      @NonNull ICastExecutor<T> castExecutor,
      @NonNull IEnhancedQName qname) {
    super(itemClass, castExecutor);
    this.qname = qname;
  }

  @Override
  public IEnhancedQName getQName() {
    return qname;
  }

  @Override
  @Nullable
  public IDataTypeAdapter<?> getAdapter() {
    // always null
    return null;
  }

  @Override
  protected int generateHashCode() {
    return Objects.hash(getItemClass(), qname);
  }

  @Override
  public int hashCode() {
    // for parity with equals
    return super.hashCode();
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof NonAdapterAtomicItemType)) {
      return false;
    }
    NonAdapterAtomicItemType<?> other = (NonAdapterAtomicItemType<?>) obj;
    return Objects.equals(getItemClass(), other.getItemClass())
        && Objects.equals(getQName(), other.getQName());
  }

  @Override
  public T newItem(Object value) {
    throw new UnsupportedOperationException("Not a conrete atomic type.");
  }
}
