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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/#func-data">fn:data</a>
 * functions.
 */
public final class FnData {
  private static final String NAME = "data";
  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IAnyAtomicItem.type())
      .returnOne()
      .functionHandler(FnData::executeNoArg)
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
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IAnyAtomicItem.type())
      .returnOne()
      .functionHandler(FnData::executeOneArg)
      .build();

  private FnData() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    INodeItem item = INodeItem.type().testOrNull(focus);

    ISequence<IAnyAtomicItem> retval;
    if (item == null) {
      retval = ISequence.empty();
    } else {
      IAnyAtomicItem data = item.toAtomicItem();
      retval = ISequence.of(data);
    }
    return retval;
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IAnyAtomicItem> executeOneArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    return ISequence.of(arguments.get(0).atomize());
  }
}
