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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-abs">fn:abs</a>
 * function.
 */
public final class FnAbs {
  private static final String NAME = "abs";

  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(INumericItem.type())
          .zeroOrOne()
          .build())
      .returnType(INumericItem.type())
      .returnZeroOrOne()
      .functionHandler(FnAbs::execute)
      .build();

  private FnAbs() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<INumericItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INumericItem item = INumericItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return item == null
        ? ISequence.empty()
        : ISequence.of(item.castAsType(item.abs()));
  }
}
