/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.impl;

import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.metapath.type.Occurrence;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.EnumSet;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides default methods for node items that represent collections of
 * Metapath items and sequences.
 */
public interface IFeatureCollectionFunctionItem extends IFunction {
  /**
   * The function properties.
   */
  @NonNull
  Set<FunctionProperty> PROPERTIES = ObjectUtils.notNull(
      EnumSet.of(FunctionProperty.DETERMINISTIC));
  /**
   * The function result.
   */
  @NonNull
  ISequenceType RESULT = ISequenceType.of(
      IAnyAtomicItem.type(), Occurrence.ZERO_OR_ONE);

  @Override
  default boolean isDeterministic() {
    return true;
  }

  @Override
  default boolean isContextDepenent() {
    return false;
  }

  @Override
  default boolean isFocusDependent() {
    return false;
  }

  @Override
  default Set<FunctionProperty> getProperties() {
    return PROPERTIES;
  }

  @Override
  default int arity() {
    return 1;
  }

  @Override
  default boolean isArityUnbounded() {
    return false;
  }

  @Override
  default ISequenceType getResult() {
    return RESULT;
  }

  @Override
  default boolean isNamedFunction() {
    // these functions are not named, since they refer to anonymous collections
    return false;
  }
}
