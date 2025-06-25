/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.DocumentFunctionException;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.io.IOException;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-doc">fn:doc</a>
 * function.
 */
public final class FnDoc {
  private static final String NAME = "doc";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .returnType(IDocumentNodeItem.type())
      .returnOne()
      .functionHandler(FnDoc::execute)
      .build();

  private FnDoc() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDocumentNodeItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem item = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return item == null
        ? ISequence.empty()
        : ISequence.of(fnDoc(item, dynamicContext));
  }

  /**
   * Dynamically load the document associated with the URI, and return a
   * {@link IDocumentNodeItem} containing the result.
   * <p>
   * Based on the XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-doc">fn:doc</a>
   * function.
   *
   * @param documentUri
   *          the resource to load the data from
   * @param context
   *          the Metapath dynamic context
   * @return the loaded document node item
   */
  public static IDocumentNodeItem fnDoc(@NonNull IStringItem documentUri, @NonNull DynamicContext context) {
    IAnyUriItem uri;
    try {
      uri = IAnyUriItem.cast(documentUri);
    } catch (MetapathException ex) {
      throw new DocumentFunctionException(DocumentFunctionException.INVALID_ARGUMENT,
          String.format("Invalid URI argument '%s' to fn:doc or fn:doc-available.", documentUri.asString()), ex);
    }

    return fnDoc(uri, context);
  }

  /**
   * Dynamically load the document associated with the URI, and return a
   * {@link IDocumentNodeItem} containing the result.
   * <p>
   * Based on the XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-doc">fn:doc</a>
   * function.
   *
   * @param documentUri
   *          the resource to load the data from
   * @param context
   *          the Metapath dynamic context
   * @return the loaded document node item
   */
  @NonNull
  public static IDocumentNodeItem fnDoc(@NonNull IAnyUriItem documentUri, @NonNull DynamicContext context) {
    // resolve if possible
    IAnyUriItem uri = FnResolveUri.fnResolveUri(documentUri, null, context);
    if (!uri.isAbsolute() && !uri.isOpaque()) {
      throw new DocumentFunctionException(DocumentFunctionException.ERROR_RETRIEVING_RESOURCE, String
          .format("No base-uri is available in the static context to resolve the URI '%s'.", documentUri.toString()));
    }

    try {
      return context.getDocumentLoader().loadAsNodeItem(ObjectUtils.notNull(uri.asUri()));
    } catch (IOException ex) {
      throw new DocumentFunctionException(DocumentFunctionException.ERROR_RETRIEVING_RESOURCE, String
          .format("Unable to retrieve the resource identified by the URI '%s'.", documentUri.asUri().toString()), ex);
    }
  }
}
