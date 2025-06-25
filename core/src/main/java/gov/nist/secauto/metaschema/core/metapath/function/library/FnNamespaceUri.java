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
import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-namespace-uri">fn:namespace-uri</a>
 * functions.
 */
public final class FnNamespaceUri {
  @NonNull
  private static final String NAME = "namespace-uri";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IStringItem.type())
      .returnOne()
      .functionHandler(FnNamespaceUri::executeNoArg)
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
      .functionHandler(FnNamespaceUri::executeOneArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    // test that the focus is an INodeItem
    INodeItem arg = INodeItem.type().test(focus);
    return ISequence.of(IStringItem.valueOf(fnNamespaceUri(arg)));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INodeItem arg = INodeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return ISequence.of(IStringItem.valueOf(arg == null ? "" : fnNamespaceUri(arg)));
  }

  /**
   * Get the namespace URI of the provided node item.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-namespace-uri">fn:namespace-uri</a>
   * function.
   *
   * @param arg
   *          the node item to get the namespace URI for
   * @return the namespace URI of the node if it has one, or an empty string
   *         otherwise
   */
  @NonNull
  public static String fnNamespaceUri(@NonNull INodeItem arg) {
    return arg instanceof IDefinitionNodeItem
        ? ((IDefinitionNodeItem<?, ?>) arg).getQName().getNamespace()
        : "";
  }

  private FnNamespaceUri() {
    // disable construction
  }
}
