/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides a convenient way to raise a
 * {@link TypeMetapathException#INVALID_TYPE_ERROR}.
 */
public class InvalidTypeMetapathException
    extends TypeMetapathException {

  /**
   * the serial version UID.
   */
  private static final long serialVersionUID = 1L;

  @Nullable
  private final IItem item;

  /**
   * Constructs a new exception with the provided {@code item} and {@code cause},
   * using a default message.
   *
   * @param item
   *          the item related to the invalid type error
   * @param cause
   *          the original exception cause
   */
  public InvalidTypeMetapathException(@NonNull IItem item, @NonNull Throwable cause) {
    super(INVALID_TYPE_ERROR, String.format("Invalid data type '%s'", item.getClass().getName()),
        cause);
    this.item = item;
  }

  /**
   * Constructs a new exception with the provided {@code item} and no cause, using
   * a default message.
   *
   * @param item
   *          the item related to the invalid type error
   */
  public InvalidTypeMetapathException(@NonNull IItem item) {
    super(INVALID_TYPE_ERROR, String.format("Invalid data type '%s'", item.getClass().getName()));
    this.item = item;
  }

  /**
   * Constructs a new exception with the provided {@code item}, {@code message},
   * and {@code cause}.
   *
   * @param item
   *          the item related to the invalid type error
   * @param message
   *          the exception message
   * @param cause
   *          the original exception cause
   */
  public InvalidTypeMetapathException(@Nullable IItem item, @Nullable String message, @NonNull Throwable cause) {
    super(INVALID_TYPE_ERROR, message, cause);
    this.item = item;
  }

  /**
   * Constructs a new exception with the provided {@code item}, {@code message},
   * and no cause.
   *
   * @param item
   *          the item related to the invalid type error
   * @param message
   *          the exception message
   */
  public InvalidTypeMetapathException(@Nullable IItem item, @Nullable String message) {
    super(INVALID_TYPE_ERROR, message);
    this.item = item;
  }

  /**
   * Get the associated item, if provided for the exception.
   *
   * @return the item or {@code null} if not item was provided
   */
  @Nullable
  public IItem getItem() {
    return item;
  }
}
