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
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-document-uri">fn:document-uri</a>
 * functions.
 */
public final class FnDocumentUri {
  private static final String NAME = "document-uri";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IAnyUriItem.type())
      .returnOne()
      .functionHandler(FnDocumentUri::executeNoArg)
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
          .type(IDocumentNodeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IAnyUriItem.type())
      .returnOne()
      .functionHandler(FnDocumentUri::executeOneArg)
      .build();

  private FnDocumentUri() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyUriItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    INodeItem item = INodeItem.type().testOrNull(focus);

    return item instanceof IDocumentNodeItem
        ? ISequence.of(fnDocumentUri((IDocumentNodeItem) item))
        : ISequence.empty();
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyUriItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    INodeItem item = INodeItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return item instanceof IDocumentNodeItem
        ? ISequence.of(fnDocumentUri((IDocumentNodeItem) item))
        : ISequence.empty();
  }

  /**
   * Get the URI of the document.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-document-uri">fn:document-uri</a>
   * function.
   *
   * @param document
   *          the document to get the URI for
   * @return the URI of the document or {@code null} if not available
   */
  @Nullable
  public static IAnyUriItem fnDocumentUri(@NonNull IDocumentNodeItem document) {
    return IAnyUriItem.valueOf(document.getDocumentUri());
  }
}
