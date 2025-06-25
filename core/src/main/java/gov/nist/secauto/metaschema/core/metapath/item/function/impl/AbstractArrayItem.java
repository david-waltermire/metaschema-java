/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function.impl;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.impl.IFeatureCollectionFunctionItem;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * The base class for {@link IArrayItem} implementations, that provides an
 * implementation of common methods.
 *
 * @param <ITEM>
 *          the Java type of the items contained within the sequence
 */
public abstract class AbstractArrayItem<ITEM extends ICollectionValue>
    extends ImmutableCollections.AbstractImmutableDelegatedList<ITEM>
    implements IArrayItem<ITEM>, IFeatureCollectionFunctionItem {
  @NonNull
  private static final IEnhancedQName QNAME = IEnhancedQName.of("array");
  @NonNull
  private static final List<IArgument> ARGUMENTS = ObjectUtils.notNull(List.of(
      IArgument.builder().name("position").type(IIntegerItem.type()).one().build()));

  @NonNull
  private static final IArrayItem<?> EMPTY = new ArrayItemN<>();

  /**
   * Get an immutable array item that is empty.
   *
   * @param <T>
   *          the item Java type
   * @return the empty array item
   */
  @SuppressWarnings("unchecked")
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> empty() {
    return (IArrayItem<T>) EMPTY;
  }

  @Override
  public IEnhancedQName getQName() {
    return QNAME;
  }

  @Override
  public List<IArgument> getArguments() {
    return ARGUMENTS;
  }

  @Override
  public ISequence<?> execute(List<? extends ISequence<?>> arguments, DynamicContext dynamicContext,
      ISequence<?> focus) {
    ISequence<? extends IIntegerItem> arg = arguments.get(0).ofType(IIntegerItem.type());
    IIntegerItem position = arg.getFirstItem(true);
    if (position == null) {
      return ISequence.empty(); // NOPMD - readability
    }

    int index = position.toIntValueExact() - 1;
    ICollectionValue result = getValue().get(index);
    return result.toSequence();
  }

  @Override
  public int hashCode() {
    return Objects.hash(getValue());
  }

  @Override
  public boolean equals(Object other) {
    return other == this
        || other instanceof IArrayItem && getValue().equals(((IArrayItem<?>) other).getValue());
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  @Override
  public boolean deepEquals(ICollectionValue other, DynamicContext dynamicContext) {
    if (!(other instanceof IArrayItem)) {
      return false;
    }

    IArrayItem<?> otherArray = (IArrayItem<?>) other;
    if (size() != otherArray.size()) {
      return false;
    }

    Iterator<? extends ICollectionValue> thisIterator = iterator();
    Iterator<? extends ICollectionValue> otherIterator = otherArray.iterator();
    boolean retval = true;
    while (thisIterator.hasNext() && otherIterator.hasNext()) {
      ICollectionValue i1 = thisIterator.next();
      ICollectionValue i2 = otherIterator.next();
      if (!i1.deepEquals(i2, dynamicContext)) {
        retval = false;
        break;
      }
    }
    return retval;
  }

  @Override
  public String toSignature() {
    return ObjectUtils.notNull(stream()
        .map(ICollectionValue::toSignature)
        .collect(Collectors.joining(",", "[", "]")));
  }

  @Override
  public String toString() {
    return toSignature();
  }
}
