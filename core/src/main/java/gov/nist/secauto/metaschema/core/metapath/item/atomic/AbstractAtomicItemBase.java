/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.function.ComparisonFunctions;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides base functionality for atomic item implementations.
 *
 * @param <TYPE>
 *          the Java type of the underlying data value
 */
public abstract class AbstractAtomicItemBase<TYPE> implements IAnyAtomicItem {

  @Override
  @NonNull
  public abstract IDataTypeAdapter<TYPE> getJavaTypeAdapter();

  @Override
  public String asString() {
    return getJavaTypeAdapter().asString(getValue());
  }

  @Override
  public String toSignature() {
    return ObjectUtils.notNull(new StringBuilder()
        .append(getType().toSignature())
        .append('(')
        .append(getValueSignature())
        .append(')')
        .toString());
  }

  /**
   * Get the string to use for the item's value in the item's signature.
   *
   * @return the value string
   */
  @NonNull
  protected abstract String getValueSignature();

  @NonNull
  @Override
  public String toString() {
    return toSignature();
  }

  @Override
  public boolean deepEquals(ICollectionValue other, DynamicContext dynamicContext) {
    return handleDeepEquals(other, dynamicContext);
  }

  /**
   * Determine if this and the other value are deeply equal, without relying on
   * the dynamic context.
   * <p>
   * Item equality is defined by the
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-deep-equal">XPath 3.1
   * fn:deep-equal</a> specification.
   *
   * @param other
   *          the other value to compare to this value to
   * @return the {@code true} if the two values are equal, or {@code false}
   *         otherwise
   */
  @Override
  public boolean deepEquals(@Nullable ICollectionValue other) {
    return handleDeepEquals(other, null);
  }

  private boolean handleDeepEquals(
      @Nullable ICollectionValue other,
      @Nullable DynamicContext dynamicContext) {
    boolean retval;
    try {
      retval = other instanceof IAnyAtomicItem
          && ComparisonFunctions.valueCompairison(
              this,
              ComparisonFunctions.Operator.EQ,
              (IAnyAtomicItem) other,
              dynamicContext)
              .toBoolean();
    } catch (InvalidTypeMetapathException ex) {
      // incompatible types are a non-match
      retval = false;
    }
    return retval;
  }
}
