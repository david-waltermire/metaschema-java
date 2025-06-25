/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-deep-equal">fn:deep-equal</a>
 * functions.
 * <p>
 * This implementation does not implement the three-arg variant with collation
 * at this time.
 */
public final class FnDeepEqual {
  @NonNull
  private static final String NAME = "deep-equal";
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("parameter1")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("parameter2")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IBooleanItem.type())
      .returnOne()
      .functionHandler(FnDeepEqual::executeTwoArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> executeTwoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<?> parameter1 = ObjectUtils.requireNonNull(arguments.get(0));
    ISequence<?> parameter2 = ObjectUtils.requireNonNull(arguments.get(1));
    return ISequence.of(IBooleanItem.valueOf(parameter1.deepEquals(parameter2, dynamicContext)));
  }

  private FnDeepEqual() {
    // disable construction
  }
}
