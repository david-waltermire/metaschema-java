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

import java.util.ArrayList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-insert-before">fn:insert-before</a>
 * function.
 */
public final class FnInsertBefore {
  private static final String NAME = "insert-before";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("target")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .argument(IArgument.builder()
          .name("position")
          .type(IIntegerItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("inserts")
          .type(IItem.type())
          .zeroOrMore()
          .build())
      .returnType(IItem.type())
      .returnZeroOrMore()
      .functionHandler(FnInsertBefore::execute)
      .build();

  private FnInsertBefore() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<IItem> target = arguments.get(0).ofType(IItem.type());

    IIntegerItem position = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));
    ISequence<IItem> inserts = arguments.get(2).ofType(IItem.type());
    return ISequence.ofCollection(fnInsertBefore(target, position, inserts));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-insert-before">fn:insert-before</a>.
   *
   * @param <T>
   *          the type for the given Metapath sequence
   * @param target
   *          the sequence of Metapath items that is the target of insertion
   * @param positionItem
   *          the integer position of the item to insert before
   * @param inserts
   *          the sequence of Metapath items to be inserted into the target
   * @return the sequence of Metapath items with insertions
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  public static <T extends IItem> List<T> fnInsertBefore(
      @NonNull List<T> target,
      @NonNull IIntegerItem positionItem,
      @NonNull List<T> inserts) {
    if (target.isEmpty()) {
      return inserts;
    }

    if (inserts.isEmpty()) {
      return target;
    }

    int position = positionItem.toIntValueExact();

    if (position < 1) {
      position = 1;
    } else if (position > target.size()) {
      position = target.size() + 1;
    }

    List<T> newSequence = new ArrayList<>(target.size() + inserts.size());

    if (position == 1) {
      newSequence.addAll(inserts);
      newSequence.addAll(target);
    } else {
      newSequence.addAll(target.subList(0, position - 1));
      newSequence.addAll(inserts);
      newSequence.addAll(target.subList(position - 1, target.size()));
    }
    return newSequence;
  }
}
