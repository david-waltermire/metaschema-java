/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;

import java.util.ArrayList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-array-append">array:append</a>
 * function.
 */
public final class ArrayAppend {
  private static final String NAME = "append";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_ARRAY)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("array")
          .type(IArrayItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("appendage")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IArrayItem.type())
      .returnOne()
      .functionHandler(ArrayAppend::execute)
      .build();

  private ArrayAppend() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static <T extends ICollectionValue> ISequence<IArrayItem<T>> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<T> array = IArrayItem.type().ofType(arguments.get(0).getFirstItem(true));
    @SuppressWarnings("unchecked")
    T appendage = (T) arguments.get(1).toCollectionValue();

    return ISequence.of(append(array, appendage));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-append">array:append</a>.
   *
   * @param <T>
   *          the type of items in the given Metapath array
   * @param array
   *          the target Metapath array
   * @param appendage
   *          the Metapath item to append to the identified array
   * @return a new array containing the modification
   */
  @NonNull
  public static <T extends ICollectionValue> IArrayItem<T> append(
      @NonNull IArrayItem<T> array,
      @NonNull T appendage) {

    List<T> copy = new ArrayList<>(array);
    copy.add(appendage);

    return IArrayItem.ofCollection(copy);
  }
}
