/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.adapter.DecimalAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of a Metapath atomic item containing a decimal data value.
 */
public class DecimalItemImpl
    extends AbstractDecimalItem<BigDecimal> {
  @NonNull
  private static final BigDecimal BOOLEAN_TRUE = new BigDecimal("1.0");
  @NonNull
  private static final BigDecimal BOOLEAN_FALSE = new BigDecimal("0.0");

  /**
   * Get the equivalent decimal value for the provided boolean value.
   *
   * @param value
   *          the boolean value
   * @return the equivalent decimal value
   */
  @NonNull
  public static BigDecimal toBigDecimal(boolean value) {
    return value ? BOOLEAN_TRUE : BOOLEAN_FALSE;
  }

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public DecimalItemImpl(@NonNull BigDecimal value) {
    super(value);
  }

  @Override
  public DecimalAdapter getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.DECIMAL;
  }

  @Override
  public BigDecimal asDecimal() {
    return getValue();
  }

  @SuppressWarnings("null")
  @Override
  public String asString() {
    BigDecimal decimal = getValue();
    // if the fractional part is empty, render as an integer
    return decimal.scale() <= 0 ? decimal.toBigIntegerExact().toString() : decimal.toPlainString();
  }

  @SuppressWarnings("null")
  @Override
  public BigInteger asInteger() {
    return getValue().toBigInteger();
  }

  @Override
  public int hashCode() {
    return Objects.hash(asDecimal());
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IDecimalItem && compareTo((IDecimalItem) obj) == 0;
  }
}
