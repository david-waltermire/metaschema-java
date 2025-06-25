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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-has-children">fn:has-children</a>
 * functions.
 */
public final class FnHasChildren {
  @NonNull
  private static final String NAME = "has-children";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnHasChildren::executeNoArg)
      .build();
  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(INodeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IBooleanItem.type())
      .returnOne()
      .functionHandler(FnHasChildren::executeOneArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    // test that the focus is an INodeItem
    INodeItem arg = INodeItem.type().test(focus);

    return ISequence.of(IBooleanItem.valueOf(fnHasChildren(arg)));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INodeItem arg = INodeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null ? ISequence.empty() : ISequence.of(IBooleanItem.valueOf(fnHasChildren(arg)));
  }

  /**
   * Determine if the provided node argument has model item children.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-has-children">fn:has-children</a>
   * function.
   *
   * @param arg
   *          the node item to check for children
   * @return {@code true} if the provided node has model item children, or
   *         {@code false} otherwise
   */
  public static boolean fnHasChildren(@NonNull INodeItem arg) {
    return arg.modelItems().findFirst().isPresent();
  }

  private FnHasChildren() {
    // disable construction
  }
}
