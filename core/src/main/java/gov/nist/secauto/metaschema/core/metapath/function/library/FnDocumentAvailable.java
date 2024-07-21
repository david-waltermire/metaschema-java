/*
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.DocumentFunctionException;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

public final class FnDocumentAvailable {

  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name("doc-available")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(IStringItem.class)
          .zeroOrOne()
          .build())
      .returnType(IBooleanItem.class)
      .returnOne()
      .functionHandler(FnDocumentAvailable::execute)
      .build();

  private FnDocumentAvailable() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBooleanItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments, @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<? extends IStringItem> arg = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(0)));

    IStringItem item = arg.getFirstItem(true);

    return item == null ? ISequence.empty() : ISequence.of(fnDocAvailable(item, dynamicContext));
  }

  /**
   * Test if the document associated with the URI is retrievable.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-doc-available">fn:doc</a>
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
   * "https://www.w3.org/TR/xpath-functions-31/#func-doc-available">fn:doc</a>
   * function.
   *
   * @param documentUri
   *          the resource to load the data from
   * @param context
   *          the Metapath dynamic context
   * @return if the document is retrievable
   */
  public static IBooleanItem fnDocAvailable(@NonNull IAnyUriItem documentUri, @NonNull DynamicContext context) {
    // resolve if possible
    IAnyUriItem uri = FnResolveUri.fnResolveUri(documentUri, null, context);
    if (!uri.isAbsolute() && !uri.isOpaque()) {
      throw new DocumentFunctionException(DocumentFunctionException.ERROR_RETRIEVING_RESOURCE, String
          .format("No base-uri is available in the static context to resolve the URI '%s'.", documentUri.toString()));
    }

    boolean retval;
    try {
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
      return IBooleanItem.valueOf(retval);
    } catch (IOException ex) {
      throw new DocumentFunctionException(DocumentFunctionException.ERROR_RETRIEVING_RESOURCE, String
          .format("Unable to retrieve the resource identified by the URI '%s'.", documentUri.toString()), ex);
    }
  }
}
