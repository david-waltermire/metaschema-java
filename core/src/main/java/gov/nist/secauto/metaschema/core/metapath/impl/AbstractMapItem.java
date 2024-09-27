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
import gov.nist.secauto.metaschema.core.metapath.function.library.MapGet;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.metapath.type.Occurrence;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

public abstract class AbstractMapItem<VALUE extends ICollectionValue>
    extends ImmutableCollections.AbstractImmutableDelegatedMap<IMapKey, VALUE>
    implements IMapItem<VALUE> {
  @NonNull
  public static final QName QNAME = new QName("map");
  @NonNull
  public static final Set<FunctionProperty> PROPERTIES = ObjectUtils.notNull(
      EnumSet.of(FunctionProperty.DETERMINISTIC));
  @NonNull
  public static final List<IArgument> ARGUMENTS = ObjectUtils.notNull(List.of(
      IArgument.builder().name("key").type(IAnyAtomicItem.class).one().build()));
  @NonNull
  public static final ISequenceType RESULT = ISequenceType.of(IAnyAtomicItem.class, Occurrence.ZERO_OR_ONE);

  @NonNull
  private static final IMapItem<?> EMPTY = new MapItemN<>();

  /**
   * Get an immutable map item that is empty.
   *
   * @param <T>
   *          the item Java type
   * @return the empty map item
   */

  @SuppressWarnings("unchecked")
  @NonNull
  public static <V extends ICollectionValue> IMapItem<V> empty() {
    return (IMapItem<V>) EMPTY;
  }

  @Override
  public ISequence<?> execute(List<ISequence<?>> arguments, DynamicContext dynamicContext,
      ISequence<?> focus) {
    ISequence<? extends IIntegerItem> arg = FunctionUtils.asType(
        ObjectUtils.notNull(arguments.get(0)));

    IAnyAtomicItem key = arg.getFirstItem(true);
    if (key == null) {
      return ISequence.empty(); // NOPMD - readability
    }

    ICollectionValue result = MapGet.get(this, key);
    return result == null ? ISequence.empty() : result.asSequence();
  }

  @Override
  public int hashCode() {
    return Objects.hash(getValue());
  }

  @Override
  public boolean equals(Object other) {
    return other == this
        || other instanceof IMapItem && getValue().equals(((IMapItem<?>) other).getValue());
  }

  @Override
  public String asString() {
    return ObjectUtils.notNull(toString());
  }
}
