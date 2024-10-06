/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-current-dateTime">fn:current-dateTime</a>.
 */
public final class FnCurrentDateTime {
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name("true")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .returnType(IDateTimeItem.class)
      .returnOne()
      .functionHandler(FnCurrentDateTime::execute)
      .build();

  private FnCurrentDateTime() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDateTimeItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    return ISequence.of(fnCurrentDateTime(dynamicContext));
  }
  
  @NonNull
  public static IDateTimeItem fnCurrentDateTime(@NonNull DynamicContext dynamicContext) {
    return IDateTimeItem.valueOf( dynamicContext.getCurrentDateTime());
  }
}
