/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import java.math.BigInteger;

import edu.umd.cs.findbugs.annotations.NonNull;

// TODO: extends IDecimalItem instead
public interface IIntegerItem extends IDecimalItem {

  @SuppressWarnings("null")
  @NonNull
  IIntegerItem ONE = valueOf(BigInteger.ONE);
  @SuppressWarnings("null")
  @NonNull
  IIntegerItem ZERO = valueOf(BigInteger.ZERO);
  @SuppressWarnings("null")
  @NonNull
  IIntegerItem NEGATIVE_ONE = valueOf(BigInteger.ONE.negate());

  /**
   * Create an item from an existing integer value.
   *
   * @param value
   *          a string representing an integer value
   * @return the item
   * @throws InvalidTypeMetapathException
   *           if the provided value is not an integer
   */
  @NonNull
  static IIntegerItem valueOf(@NonNull String value) {
    try {
      return valueOf(new BigInteger(value));
    } catch (NumberFormatException ex) {
      throw new InvalidTypeMetapathException(null,
          ex.getMessage(),
          ex);
    }
  }

  /**
   * Construct a new integer item using the provided {@code value}.
   *
   * @param value
   *          a long value
   * @return the new item
   */
  @NonNull
  static IIntegerItem valueOf(int value) {
    @SuppressWarnings("null")
    @NonNull BigInteger bigInteger = BigInteger.valueOf(value);
    return valueOf(bigInteger);
  }

  /**
   * Construct a new integer item using the provided {@code value}.
   *
   * @param value
   *          a long value
   * @return the new item
   */
  @NonNull
  static IIntegerItem valueOf(long value) {
    @SuppressWarnings("null")
    @NonNull BigInteger bigInteger = BigInteger.valueOf(value);
    return valueOf(bigInteger);
  }

  /**
   * Construct a new integer item using the provided {@code value}.
   *
   * @param value
   *          an integer value
   * @return the new item
   */
  @NonNull
  static IIntegerItem valueOf(@NonNull BigInteger value) {
    int signum = value.signum();

    IIntegerItem retval;
    if (signum == -1) { // negative
      retval = new IntegerItemImpl(value);
    } else if (signum == 0) { // zero
      retval = INonNegativeIntegerItem.valueOf(value);
    } else { // positive
      retval = IPositiveIntegerItem.valueOf(value);
    }
    return retval;
  }

  /**
   * Cast the provided type to this item type.
   *
   * @param item
   *          the item to cast
   * @return the original item if it is already this type, otherwise a new item
   *         cast to this type
   * @throws InvalidValueForCastFunctionException
   *           if the provided {@code item} cannot be cast to this type
   */
  @NonNull
  static IIntegerItem cast(@NonNull IAnyAtomicItem item) {
    return MetaschemaDataTypeProvider.INTEGER.cast(item);
  }

  @Override
  IIntegerItem abs();

  @Override
  default IIntegerItem ceiling() {
    return this;
  }

  @Override
  default IIntegerItem floor() {
    return this;
  }

  @Override
  default IIntegerItem castAsType(IAnyAtomicItem item) {
    return valueOf(cast(item).asInteger());
  }

  @Override
  default int compareTo(IAnyAtomicItem item) {
    return compareTo(cast(item));
  }

  /**
   * Compares this value with the argument.
   *
   * @param item
   *          the item to compare with this value
   * @return a negative integer, zero, or a positive integer if this value is less
   *         than, equal to, or greater than the {@code item}.
   */
  default int compareTo(IIntegerItem item) {
    return asInteger().compareTo(item.asInteger());
  }
}
