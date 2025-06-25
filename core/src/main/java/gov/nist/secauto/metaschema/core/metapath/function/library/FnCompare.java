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
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-compare">fn:compare</a>
 * function.
 */
public final class FnCompare {
  private static final String NAME = "compare";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("comparand1")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("comparand2")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .returnType(IIntegerItem.type())
      .returnZeroOrOne()
      .functionHandler(FnCompare::execute)
      .build();

  private FnCompare() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> execute(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem comparand1 = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    IStringItem comparand2 = IStringItem.type().ofTypeOrNull(arguments.get(1).getFirstItem(true));

    ISequence<IIntegerItem> retval;
    if (comparand1 == null || comparand2 == null) {
      retval = ISequence.empty();
    } else {
      IIntegerItem result = IIntegerItem.valueOf(comparand1.compareTo(comparand2));
      retval = ISequence.of(result);
    }
    return retval;
  }
}
