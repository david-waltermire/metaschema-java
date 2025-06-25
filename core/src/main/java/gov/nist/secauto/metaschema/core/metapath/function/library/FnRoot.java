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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-root">fn:root</a>
 * functions.
 */
public final class FnRoot {
  @NonNull
  private static final String NAME = "root";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnRoot::executeNoArg)
      .build();
  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusDependent()
      .argument(IArgument.builder()
          .name("arg")
          .type(INodeItem.type())
          .zeroOrOne()
          .build())
      .returnType(INodeItem.type())
      .returnZeroOrOne()
      .functionHandler(FnRoot::executeOneArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<INodeItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    // test that the focus is an INodeItem
    INodeItem arg = INodeItem.type().test(focus);
    return ISequence.of(fnRoot(arg));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<INodeItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INodeItem arg = INodeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return arg == null ? ISequence.empty() : ISequence.of(fnRoot(arg));
  }

  /**
   * Get the root of the tree to which the provided node argument belongs.
   * <p>
   * Based on the XPath 3.1
   * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-root">fn:root</a>
   * function.
   *
   * @param arg
   *          the node item to get the namespace URI for
   * @return the root of the tree to which the provided node argument belongs
   */
  @NonNull
  public static INodeItem fnRoot(@NonNull INodeItem arg) {
    INodeItem retval = arg;
    while (retval.getParentNodeItem() != null) {
      retval = retval.getParentNodeItem();
    }

    return retval;
  }

  private FnRoot() {
    // disable construction
  }
}
