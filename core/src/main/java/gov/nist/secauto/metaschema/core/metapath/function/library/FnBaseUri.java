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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.net.URI;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-base-uri">fn:base-uri</a>
 * functions.
 * <p>
 * Since a node doesn't have a base URI in Metaschema, this is an alias for the
 * document-uri function, since the node's base URI is the same as the
 * document's URI.
 */
public final class FnBaseUri {
  private static final String NAME = "base-uri";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IAnyUriItem.type())
      .returnOne()
      .functionHandler(FnBaseUri::executeNoArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(INodeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IAnyUriItem.type())
      .returnOne()
      .functionHandler(FnBaseUri::executeOneArg)
      .build();

  private FnBaseUri() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyUriItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    return ISequence.of(fnBaseUri(INodeItem.type().testOrNull(focus)));
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyUriItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    return ISequence.of(fnBaseUri(INodeItem.type().ofType(arguments.get(0).getFirstItem(true))));
  }

  /**
   * Get the base URI for the provided {@code nodeItem}.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-base-uri">fn:base-uri</a>
   * function.
   *
   * @param nodeItem
   *          the node to get the base URI from
   * @return the base URI, or {@code null} if the node is either null or doesn't
   *         have a base URI
   */
  @SuppressWarnings("PMD.NullAssignment") // for readability
  @Nullable
  public static IAnyUriItem fnBaseUri(INodeItem nodeItem) {
    IAnyUriItem retval;
    if (nodeItem == null) {
      retval = null;
    } else {
      URI baseUri = nodeItem.getBaseUri();
      retval = baseUri == null ? null : IAnyUriItem.valueOf(baseUri);
    }
    return retval;
  }
}
