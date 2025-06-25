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
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-tail">fn:tail</a>
 * function.
 */
public final class FnTail {
  private static final String NAME = "tail";
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
      .returnType(IItem.type())
      .returnZeroOrMore()
      .functionHandler(FnTail::execute)
      .build();

  private FnTail() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<?> items = ObjectUtils.requireNonNull(arguments.get(0));
    return ISequence.ofCollection(fnTail(items));
  }

  /**
   * Return the last item in the {@code sequence}.
   *
   * @param sequence
   *          the sequence to check
   * @return {@code IItem} the last item in the sequence {@code null} otherwise
   *         null for no items
   */
  @NonNull
  public static List<? extends IItem> fnTail(@NonNull List<? extends IItem> sequence) {
    return sequence.size() <= 1
        ? CollectionUtil.emptyList()
        : ObjectUtils.notNull(sequence.subList(1, sequence.size()));
  }
}
