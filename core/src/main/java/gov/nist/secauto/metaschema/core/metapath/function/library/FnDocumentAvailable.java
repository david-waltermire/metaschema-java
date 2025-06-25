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
import gov.nist.secauto.metaschema.core.metapath.function.UriFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-doc-available">fn:doc-available</a>
 * function.
 */
public final class FnDocumentAvailable {
  private static final String NAME = "doc-available";
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
      .returnType(IBooleanItem.type())
      .returnOne()
      .functionHandler(FnDocumentAvailable::execute)
      .build();

  private FnDocumentAvailable() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem item = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    return item == null
        ? ISequence.empty()
        : ISequence.of(fnDocAvailable(item, dynamicContext));
  }

  /**
   * Test if the document associated with the URI is retrievable.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-doc-available">fn:doc-available</a>
   * function.
   *
   * @param documentUri
   *          the resource to load the data from
   * @param context
   *          the Metapath dynamic context
   * @return if the document is retrievable
   */
  public static IBooleanItem fnDocAvailable(@NonNull IStringItem documentUri, @NonNull DynamicContext context) {
    IAnyUriItem uri;
    try {
      uri = IAnyUriItem.cast(documentUri);
    } catch (MetapathException ex) {
      throw new DocumentFunctionException(DocumentFunctionException.INVALID_ARGUMENT,
          String.format("Invalid URI argument '%s' to fn:doc or fn:doc-available.", documentUri.asString()), ex);
    }

    return fnDocAvailable(uri, context);
  }

  /**
   * Test if the document associated with the URI is retrievable.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-doc-available">fn:doc-available</a>
   * function.
   *
   * @param documentUri
   *          the resource to load the data from
   * @param context
   *          the Metapath dynamic context
   * @return if the document is retrievable
   */
  public static IBooleanItem fnDocAvailable(@NonNull IAnyUriItem documentUri, @NonNull DynamicContext context) {
    boolean retval;
    IAnyUriItem uri;
    try {
      uri = documentUri.isAbsolute() || documentUri.isOpaque()
          ? documentUri
          // if not absolute or opaque, then resolve it to make it absolute
          : FnResolveUri.fnResolveUri(documentUri, null, context);
      URLConnection connection = uri.asUri().toURL().openConnection();

      if (connection instanceof HttpURLConnection) {
        HttpURLConnection httpConnection = (HttpURLConnection) connection;
        httpConnection.setRequestMethod("HEAD");
        httpConnection.connect();
        retval = HttpURLConnection.HTTP_OK == httpConnection.getResponseCode();
        httpConnection.disconnect();
      } else {
        connection.connect();
        retval = true;
      }
    } catch (IOException | UriFunctionException ex) {
      // an error occurred while retrieving, report false
      retval = false;
    }
    return IBooleanItem.valueOf(retval);
  }
}
