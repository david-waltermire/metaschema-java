/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IQNameItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-function-lookup">fn:function-lookup</a>
 * functions.
 */
public final class FnFunctionLookup {
  @NonNull
  private static final String NAME = "function-lookup";

  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("name")
          .type(IQNameItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("arity")
          .type(IIntegerItem.type())
          .one()
          .build())
      .returnType(IItemType.function())
      .returnZeroOrOne()
      .functionHandler(FnFunctionLookup::execute)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IFunction> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IQNameItem name = IQNameItem.type().ofType(arguments.get(0).getFirstItem(true));
    IIntegerItem arity = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));
    IFunction matchingFunction = null;

    try {
      matchingFunction = dynamicContext.lookupFunction(
          name.toEnhancedQName(),
          arity.toIntValueExact());
    } catch (StaticMetapathException ex) {
      if (ex.getErrorCode().getCode() != StaticMetapathException.NO_FUNCTION_MATCH) {
        // this is something other than a non-match
        throw ex;
      }
    }

    return ISequence.of(matchingFunction);
  }

  private FnFunctionLookup() {
    // disable construction
  }
}
