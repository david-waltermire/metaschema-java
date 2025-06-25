
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides methods for comparing nodes according to the
 * <a href="https://www.w3.org/TR/xpath-functions-31/#func-deep-equal">Metapath
 * specification</a>.
 */
public final class NodeComparators {
  private static final Comparator<IFlagNodeItem> FLAG_SORT
      = Comparator.comparing(IFlagNodeItem::getQName, IEnhancedQName::compareTo);

  /**
   * Compare two node items for equality.
   *
   * @param item1
   *          the first item to compare
   * @param item2
   *          the second item to compare
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return {@code true} if both node items are the same type and have the same
   *         flag and model members, or {@code false} otherwise
   */
  public static boolean compareNodeItem(
      @NonNull INodeItem item1,
      @NonNull INodeItem item2,
      @NonNull DynamicContext dynamicContext) {
    return item1.getNodeType().equals(item2.getNodeType())
        && compareFlags(item1.getFlags(), item2.getFlags(), dynamicContext)
        && compareModelItems(item1.getModelItems(), item2.getModelItems(), dynamicContext);
  }

  private static boolean compareAtomics(
      @Nullable IAnyAtomicItem atomic1,
      @Nullable IAnyAtomicItem atomic2,
      @NonNull DynamicContext dynamicContext) {
    return atomic1 == null && atomic2 == null || atomic1 != null && atomic1.deepEquals(atomic2, dynamicContext);
  }

  /**
   * Compare two node items for equality.
   *
   * @param item1
   *          the first item to compare
   * @param item2
   *          the second item to compare
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return a negative integer, zero, or a positive integer if the first argument
   *         is less than, equal to, or greater than the second.
   */
  public static boolean compareModelNodeItem(
      @NonNull IModelNodeItem<?, ?> item1,
      @NonNull IModelNodeItem<?, ?> item2,
      @NonNull DynamicContext dynamicContext) {
    boolean retval;
    if (item1 instanceof IAssemblyNodeItem) {
      retval = compareNodeItem(item1, item2, dynamicContext);
    } else if (item1 instanceof IFieldNodeItem) {
      retval = compareAsField(item1, item2, dynamicContext);
    } else {
      throw new UnsupportedOperationException("Unsupported model node item type: " + item1.getClass().getName());
    }
    return retval;
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  private static boolean compareFlags(
      @NonNull Collection<? extends IFlagNodeItem> flags1,
      @NonNull Collection<? extends IFlagNodeItem> flags2,
      @NonNull DynamicContext dynamicContext) {
    Comparator<Collection<? extends IFlagNodeItem>> bySize = Comparator.comparingInt(Collection::size);
    int delta = bySize.compare(flags1, flags2);
    if (delta != 0) {
      return false;
    }

    // sort the collections to compare in an order independent way
    List<IFlagNodeItem> list1 = new ArrayList<>(flags1);
    List<IFlagNodeItem> list2 = new ArrayList<>(flags2);
    Collections.sort(list1, FLAG_SORT);
    Collections.sort(list2, FLAG_SORT);

    // compare the results
    for (int i = 0; i < list1.size(); i++) {
      if (!compareAsFlag(
          ObjectUtils.requireNonNull(list1.get(i)),
          ObjectUtils.requireNonNull(list2.get(i)),
          dynamicContext)) {
        return false;
      }
    }
    return true;
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  private static boolean compareModelItems(
      @NonNull Collection<? extends List<? extends IModelNodeItem<?, ?>>> items1,
      @NonNull Collection<? extends List<? extends IModelNodeItem<?, ?>>> items2,
      @NonNull DynamicContext dynamicContext) {
    Comparator<Collection<? extends List<? extends IModelNodeItem<?, ?>>>> bySize
        = Comparator.comparingInt(Collection::size);
    int delta = bySize.compare(items1, items2);
    if (delta != 0) {
      return false;
    }

    Iterator<? extends List<? extends IModelNodeItem<?, ?>>> thisIterator = items1.iterator();
    Iterator<? extends List<? extends IModelNodeItem<?, ?>>> otherIterator = items2.iterator();
    while (thisIterator.hasNext() && otherIterator.hasNext()) {
      List<? extends IModelNodeItem<?, ?>> l1 = thisIterator.next();
      List<? extends IModelNodeItem<?, ?>> l2 = otherIterator.next();

      Iterator<? extends IModelNodeItem<?, ?>> il1 = l1.iterator();
      Iterator<? extends IModelNodeItem<?, ?>> il2 = l2.iterator();
      while (thisIterator.hasNext() && otherIterator.hasNext()) {
        IModelNodeItem<?, ?> item1 = ObjectUtils.requireNonNull(il1.next());
        IModelNodeItem<?, ?> item2 = ObjectUtils.requireNonNull(il2.next());

        if (!compareModelNodeItem(item1, item2, dynamicContext)) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Compare two flag node items for equality.
   *
   * @param item1
   *          the first item to compare
   * @param item2
   *          the second item to compare
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return {@code true} if both flags have the same name and value, or
   *         {@code false} otherwise
   */
  public static boolean compareAsFlag(
      @NonNull IFlagNodeItem item1,
      @NonNull IFlagNodeItem item2,
      @NonNull DynamicContext dynamicContext) {
    return item1.getQName().equals(item2.getQName())
        && compareAtomics(item1.toAtomicItem(), item2.toAtomicItem(), dynamicContext);
  }

  private static boolean compareAsField(
      @NonNull IModelNodeItem<?, ?> item1,
      @NonNull IModelNodeItem<?, ?> item2,
      @NonNull DynamicContext dynamicContext) {
    return compareNodeItem(item1, item2, dynamicContext)
        && compareAtomics(item1.toAtomicItem(), item2.toAtomicItem(), dynamicContext);
  }

  private NodeComparators() {
    // disable construction
  }
}
