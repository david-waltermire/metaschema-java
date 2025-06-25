/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidValueForCastFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.impl.MarkupMultiLineItemImpl;
import gov.nist.secauto.metaschema.core.metapath.type.IAtomicOrUnionType;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An atomic Metapath item representing multiple lines of Markup.
 */
public interface IMarkupMultilineItem extends IMarkupItem {
  /**
   * Get the type information for this item.
   *
   * @return the type information
   */
  @NonNull
  static IAtomicOrUnionType<IMarkupMultilineItem> type() {
    return MarkupDataTypeProvider.MARKUP_MULTILINE.getItemType();
  }

  @Override
  default IAtomicOrUnionType<IMarkupMultilineItem> getType() {
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
  static IMarkupMultilineItem valueOf(@NonNull String value) {
    try {
      return valueOf(MarkupDataTypeProvider.MARKUP_MULTILINE.parse(value));
    } catch (IllegalArgumentException ex) {
      throw new InvalidValueForCastFunctionException(ex);
    }
  }

  /**
   * Construct a new item using the provided {@code value}.
   *
   * @param value
   *          multiple lines of markup
   * @return the new item
   */
  @NonNull
  static IMarkupMultilineItem valueOf(@NonNull MarkupMultiline value) {
    return new MarkupMultiLineItemImpl(value);
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
  static IMarkupMultilineItem cast(@NonNull IAnyAtomicItem item) {
    try {
      return item instanceof IMarkupMultilineItem
          ? (IMarkupMultilineItem) item
          : valueOf(item.asString());
    } catch (IllegalStateException | InvalidTypeMetapathException ex) {
      // asString can throw IllegalStateException exception
      throw new InvalidValueForCastFunctionException(ex);
    }
  }

  @Override
  default IMarkupMultilineItem castAsType(IAnyAtomicItem item) {
    return cast(item);
  }
}
