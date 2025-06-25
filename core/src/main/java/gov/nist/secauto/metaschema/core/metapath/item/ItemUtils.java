/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.InvalidTreatTypeDynamicMetapathException;
import gov.nist.secauto.metaschema.core.metapath.cst.path.Axis;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentBasedNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides a variety of utilities for working with Metapath items.
 */
public final class ItemUtils {

  private ItemUtils() {
    // disable construction
  }

  /**
   * Checks that the item is an {@link INodeItem}.
   *
   * @param dynamicContext
   *          the dynamic evaluation context
   * @param item
   *          the item to check
   * @return the item cast to a {@link INodeItem}
   * @throws TypeMetapathException
   *           if the item is {@code null} or not an {@link INodeItem}
   */
  // FIXME: make this a method on the type implementation
  // FIXME: Use IItemType method
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static INodeItem checkItemIsNodeItem(
      @NonNull DynamicContext dynamicContext,
      @Nullable IItem item) {
    return checkItemIsType(item, INodeItem.class, dynamicContext);
  }

  /**
   * Checks that the item is an {@link IDocumentNodeItem}.
   *
   * @param dynamicContext
   *          the dynamic evaluation context
   * @param item
   *          the item to check
   * @return the item cast to a {@link INodeItem}
   * @throws TypeMetapathException
   *           if the item is {@code null} or not an {@link INodeItem}
   */
  // FIXME: Use IItemType method
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static IDocumentBasedNodeItem checkItemIsDocumentNodeItem(
      @NonNull DynamicContext dynamicContext,
      @Nullable IItem item) {
    return checkItemIsType(item, IDocumentBasedNodeItem.class, dynamicContext);
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
  // FIXME: make this a method on the type implementation
  // FIXME: Use IItemType method
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @SuppressWarnings("unchecked")
  @NonNull
  public static <TYPE> TYPE checkItemType(@NonNull IItem item, @NonNull Class<? super TYPE> clazz) {
    if (clazz.isInstance(item)) {
      return (TYPE) item;
    }
    throw new InvalidTypeMetapathException(
        item,
        String.format(
            "The item of type '%s' is not the required type '%s'.",
            item.getClass().getName(),
            clazz.getName()));
  }

  // FIXME: Use IItemType method
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  private static <T extends IItem> T checkItemIsType(
      @Nullable IItem item,
      @NonNull Class<T> itemClass,
      @NonNull DynamicContext dynamicContext) {
    if (itemClass.isInstance(item)) {
      return ObjectUtils.notNull(itemClass.cast(item));
    }
    if (item == null) {
      throw new TypeMetapathException(TypeMetapathException.NOT_A_NODE_ITEM_FOR_STEP, "Item is null.")
          .registerEvaluationContext(dynamicContext);
    }
    throw new TypeMetapathException(
        TypeMetapathException.NOT_A_NODE_ITEM_FOR_STEP,
        String.format("The item of type '%s' is not of the type '%s'.",
            item.getClass().getName(),
            itemClass.getName()))
                .registerEvaluationContext(dynamicContext);
  }

  /**
   * Get the ancestor document nodes for the provided items.
   * <p>
   * The resulting sequence has items of the {@link IDocumentBasedNodeItem} to
   * allow for both module and document querying.
   *
   * @param dynamicContext
   *          the Metapath execution context
   * @param items
   *          the node items to get the document roots for
   * @return the document root node items
   */
  // FIXME: Add to INodeItem
  @Deprecated(since = "3.0.0.M1", forRemoval = true)
  @NonNull
  public static ISequence<IDocumentBasedNodeItem> getDocumentNodeItems(
      @NonNull DynamicContext dynamicContext,
      @NonNull ISequence<?> items) {
    return ISequence.of(ObjectUtils.notNull(items.stream()
        // ensures a non-null INodeItem instance
        .map(item -> checkItemIsNodeItem(dynamicContext, item))
        .map(item -> Axis.ANCESTOR_OR_SELF.execute(ObjectUtils.notNull(item))
            .findFirst().stream()
            .filter(IDocumentBasedNodeItem.class::isInstance)
            .map(firstItem -> checkItemIsDocumentNodeItem(dynamicContext, firstItem))
            .findFirst().orElseThrow(() -> new InvalidTreatTypeDynamicMetapathException(
                String.format("The node '%s' is not the descendant of a document node.",
                    item.getMetapath()))
                        .registerEvaluationContext(dynamicContext)))));
  }
}
