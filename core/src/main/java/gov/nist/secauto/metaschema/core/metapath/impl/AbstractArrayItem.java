/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.impl;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.metapath.type.Occurrence;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

public abstract class AbstractArrayItem<ITEM extends ICollectionValue>
    extends ImmutableCollections.AbstractImmutableDelegatedList<ITEM>
    implements IArrayItem<ITEM> {
  @NonNull
  public static final QName QNAME = new QName("array");
  @NonNull
  public static final Set<FunctionProperty> PROPERTIES = ObjectUtils.notNull(
      EnumSet.of(FunctionProperty.DETERMINISTIC));
  @NonNull
  public static final List<IArgument> ARGUMENTS = ObjectUtils.notNull(List.of(
      IArgument.builder().name("position").type(IIntegerItem.class).one().build()));
  @NonNull
  public static final ISequenceType RESULT = ISequenceType.of(IAnyAtomicItem.class, Occurrence.ZERO_OR_ONE);

  @SuppressWarnings({ "rawtypes", "unchecked" })
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
  public ISequence<?> execute(List<ISequence<?>> arguments, DynamicContext dynamicContext,
      ISequence<?> focus) {
    ISequence<? extends IIntegerItem> arg = FunctionUtils.asType(
        ObjectUtils.notNull(arguments.get(0)));

    IIntegerItem position = arg.getFirstItem(true);
    if (position == null) {
      return ISequence.empty(); // NOPMD - readability
    }

    int index = position.asInteger().intValueExact() - 1;
    ICollectionValue result = getValue().get(index);
    return result.asSequence();
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

  @Override
  public String asString() {
    return ObjectUtils.notNull(toString());
  }
}
