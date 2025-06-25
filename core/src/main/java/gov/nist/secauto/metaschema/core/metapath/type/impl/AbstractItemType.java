/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.type.AbstractItemTypeBase;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A common base class for item type implementations.
 *
 * @param <T>
 *          the Java type of the item supported by the implementation
 */
public abstract class AbstractItemType<T extends IItem>
    extends AbstractItemTypeBase {
  @NonNull
  private final Class<T> itemClass;

  /**
   * Construct a new item type.
   *
   * @param itemClass
   *          the item class this type supports
   */
  protected AbstractItemType(@NonNull Class<T> itemClass) {
    this.itemClass = itemClass;
  }

  @Override
  public Class<T> getItemClass() {
    return itemClass;
  }
}
