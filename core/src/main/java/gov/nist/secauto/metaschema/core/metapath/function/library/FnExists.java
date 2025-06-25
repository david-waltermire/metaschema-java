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
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-exists">fn:exists</a>
 * function.
 */
public final class FnExists {
  private static final String NAME = "exists";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IBooleanItem.type())
      .returnOne()
      .functionHandler(FnExists::execute)
      .build();

  private FnExists() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<?> items = ObjectUtils.requireNonNull(arguments.get(0));
    return ISequence.of(fnExists(items));
  }

  /**
   * Identify if there is at least one item in the {@code sequence}.
   *
   * @param sequence
   *          the sequence to check
   * @return {@code true} if the sequence contains at least one item, or
   *         {@code false} otherwise
   */
  public static IBooleanItem fnExists(ISequence<?> sequence) {
    return IBooleanItem.valueOf(!sequence.isEmpty());
  }
}
