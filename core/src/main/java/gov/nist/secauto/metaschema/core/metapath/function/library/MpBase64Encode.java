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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBase64BinaryItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides a new Metapath function that encodes provided text using base64.
 */
public final class MpBase64Encode {
  private static final String NAME = "base64-encode-text";

  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_EXTENDED)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("text")
          .type(IStringItem.type())
          .one()
          .build())
      .returnType(IBase64BinaryItem.type())
      .returnOne()
      .functionHandler(MpBase64Encode::executeOneArg)
      .build();

  private MpBase64Encode() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IBase64BinaryItem> executeOneArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem text = IStringItem.type().ofType(arguments.get(0).getFirstItem(true));
    return ISequence.of(text.encode());
  }
}
