/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.adapter.DecimalAdapter;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;

import java.math.BigDecimal;
import java.math.BigInteger;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An abstract implementation of a Metapath atomic item containing an integer
 * data value.
 */
public abstract class AbstractIntegerItem
    extends AbstractDecimalItem<BigInteger>
    implements IIntegerItem {
  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  protected AbstractIntegerItem(@NonNull BigInteger value) {
    super(value);
  }

  @Override
  public boolean toEffectiveBoolean() {
    return !BigInteger.ZERO.equals(asInteger());
  }

  @Override
  public BigDecimal asDecimal() {
    return new BigDecimal(getValue(), DecimalAdapter.mathContext());
  }

  @Override
  public BigInteger asInteger() {
    return getValue();
  }

  @Override
  public int hashCode() {
    return asInteger().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IIntegerItem && compareTo((IIntegerItem) obj) == 0;
  }
}
