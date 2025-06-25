/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-name">fn:name</a>
 * functions.
 */
public final class FnName {
  @NonNull
  private static final String NAME = "name";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnName::executeNoArg)
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
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnName::executeOneArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeNoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    // test that the focus is an INodeItem
    INodeItem arg = INodeItem.type().test(focus);
    return ISequence.of(IStringItem.valueOf(fnName(arg, dynamicContext.getStaticContext())));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INodeItem arg = INodeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return ISequence.of(
        IStringItem.valueOf(arg == null ? "" : fnName(arg, dynamicContext.getStaticContext())));
  }

  /**
   * Get the name of the provided node item.
   * <p>
   * Based on the XPath 3.1
   * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-name">fn:name</a>
   * function.
   *
   * @param arg
   *          the node item to get the name for
   * @param staticContext
   *          the static context used to resolve the namespace prefix
   * @return the name of the node if it has one, or an empty string otherwise
   */
  @NonNull
  public static String fnName(@NonNull INodeItem arg, @NonNull StaticContext staticContext) {
    return arg instanceof IDefinitionNodeItem
        ? ((IDefinitionNodeItem<?, ?>) arg).getQName().toEQName(staticContext)
        : "";
  }

  private FnName() {
    // disable construction
  }
}
