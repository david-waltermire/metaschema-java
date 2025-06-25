/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.ComparisonFunctions;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-index-of">fn:index-of</a>
 * functions. This implementation does not implement the three-arg variant with
 * collation at this time.
 */
public final class FnIndexOf {
  @NonNull
  private static final String NAME = "index-of";
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("seq")
          .type(IAnyAtomicItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("search")
          .type(IAnyAtomicItem.type())
          .one()
          .build())
      .returnType(IIntegerItem.type())
      .returnZeroOrMore()
      .functionHandler(FnIndexOf::executeTwoArg)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> executeTwoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IAnyAtomicItem> seq = arguments.get(0).ofType(IAnyAtomicItem.type());
    IAnyAtomicItem search = IAnyAtomicItem.type().ofType(arguments.get(1).getFirstItem(true));

    return seq.isEmpty() ? ISequence.empty() : fnIndexOf(seq, search, dynamicContext);
  }

  /**
   * Determine if the string provided in the first argument contains the string in
   * the second argument as a substring.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-index-of">fn:index-of</a>
   * function.
   *
   * @param items
   *          the items to match against
   * @param search
   *          the item to match
   * @param dynamicContext
   *          used to provide evaluation information, including the implicit
   *          timezone
   * @return a list of index numbers indicating the position of matches in the
   *         sequence
   */
  @NonNull
  public static ISequence<IIntegerItem> fnIndexOf(
      @NonNull List<IAnyAtomicItem> items,
      @NonNull IAnyAtomicItem search,
      @NonNull DynamicContext dynamicContext) {
    int index = 0;
    ListIterator<IAnyAtomicItem> iterator = items.listIterator();
    List<IIntegerItem> indices = new ArrayList<>();
    while (iterator.hasNext()) {
      ++index;
      IAnyAtomicItem item = iterator.next();
      assert item != null;
      // use the "eq" operator
      try {
        if (ComparisonFunctions.valueCompairison(item, ComparisonFunctions.Operator.EQ, search, dynamicContext)
            .toBoolean()) {
          // Offset for Metapath indices that start from 1
          indices.add(IIntegerItem.valueOf(index));
        }
      } catch (InvalidTypeMetapathException ex) {
        // this is an effective false on the match
      }
    }
    return ISequence.ofCollection(indices);
  }

  private FnIndexOf() {
    // disable construction
  }
}
