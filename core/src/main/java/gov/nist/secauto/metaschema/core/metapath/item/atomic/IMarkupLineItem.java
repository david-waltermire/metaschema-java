/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.impl.MarkupLineItemImpl;
import gov.nist.secauto.metaschema.core.metapath.type.IAtomicOrUnionType;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An atomic Metapath item representing a single line of Markup.
 */
public interface IMarkupLineItem extends IMarkupItem {
  /**
   * Get the type information for this item.
   *
   * @return the type information
   */
  @NonNull
  static IAtomicOrUnionType<IMarkupLineItem> type() {
    return MarkupDataTypeProvider.MARKUP_LINE.getItemType();
  }

  @Override
  default IAtomicOrUnionType<IMarkupLineItem> getType() {
    return type();
  }

  /**
   * Construct a new item using the provided {@code value}.
   *
   * @param value
   *          a line of markup
   * @return the new item
   */
  @NonNull
  static IMarkupLineItem valueOf(@NonNull String value) {
    try {
      return valueOf(MarkupDataTypeProvider.MARKUP_LINE.parse(value));
    } catch (IllegalArgumentException ex) {
      throw new InvalidValueForCastFunctionException(ex);
    }
  }

  /**
   * Construct a new item using the provided {@code value}.
   *
   * @param value
   *          a line of markup
   * @return the new item
   */
  @NonNull
  static IMarkupLineItem valueOf(@NonNull MarkupLine value) {
    return new MarkupLineItemImpl(value);
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
  static IMarkupLineItem cast(@NonNull IAnyAtomicItem item) {
    try {
      return item instanceof IMarkupLineItem
          ? (IMarkupLineItem) item
          : valueOf(item.asString());
    } catch (IllegalStateException | InvalidTypeMetapathException ex) {
      // asString can throw IllegalStateException exception
      throw new InvalidValueForCastFunctionException(ex);
    }
  }

  @Override
  default IMarkupLineItem castAsType(IAnyAtomicItem item) {
    return cast(item);
  }
}
