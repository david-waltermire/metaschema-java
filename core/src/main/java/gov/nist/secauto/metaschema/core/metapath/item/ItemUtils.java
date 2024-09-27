/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item;

import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public final class ItemUtils {

  private ItemUtils() {
    // disable construction
  }

  /**
   * Checks that the item is a node item.
   *
   * @param item
   *          the item to check
   * @return the item cast to a {@link INodeItem}
   * @throws TypeMetapathException
   *           if the item is {@code null} or not an {@link INodeItem}
   */
  @NonNull
  public static INodeItem checkItemIsNodeItemForStep(@Nullable IItem item) {
    if (item instanceof INodeItem) {
      return (INodeItem) item;
    }
    if (item == null) {
      throw new TypeMetapathException(TypeMetapathException.NOT_A_NODE_ITEM_FOR_STEP,
          "Item is null.");
    }
    throw new TypeMetapathException(TypeMetapathException.NOT_A_NODE_ITEM_FOR_STEP,
        String.format(
            "The item of type '%s' is not a INodeItem.",
            item.getClass().getName()));
  }

  /**
   * Check that the item is the type specified by {@code clazz}.
   *
   * @param <TYPE>
   *          the Java type the item is required to match
   * @param item
   *          the item to check
   * @param clazz
   *          the Java class to check the item against
   * @return the item cast to the required class value
   * @throws TypeMetapathException
   *           if the item is {@code null} or does not match the type specified by
   *           {@code clazz}
   */
  @SuppressWarnings("unchecked")
  @NonNull
  public static <TYPE> TYPE checkItemType(@NonNull IItem item, @NonNull Class<TYPE> clazz) {
    if (clazz.isInstance(item)) {
      return (TYPE) item;
    }
    throw new TypeMetapathException(TypeMetapathException.INVALID_TYPE_ERROR,
        String.format(
            "The item of type '%s' is not the required type '%s'.",
            item.getClass().getName(),
            clazz.getName()));
  }
}
