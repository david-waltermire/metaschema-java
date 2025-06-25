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
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-remove">fn:remove</a>
 * function.
 */
public final class FnRemove {
  private static final String NAME = "remove";
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
      .returnType(IItem.type())
      .returnZeroOrMore()
      .functionHandler(FnRemove::execute)
      .build();

  private FnRemove() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<?> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<?> target = ObjectUtils.requireNonNull(arguments.get(0));
    IIntegerItem position = IIntegerItem.type().ofType(arguments.get(1).getFirstItem(true));
    return ISequence.ofCollection(fnRemove(target, position));
  }

  /**
   * Remove the specified item at {@code position} from the {@code sequence}.
   *
   * @param <T>
   *          the type for the given Metapath sequence
   * @param target
   *          the sequence of Metapath items from which we will remove the item
   * @param positionItem
   *          the position of the item in the sequence to be removed
   * @return {@code sequence} the new sequence with the item removed
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  public static <T extends IItem> List<T> fnRemove(
      @NonNull List<T> target,
      @NonNull IIntegerItem positionItem) {
    int position = positionItem.toIntValueExact();

    if (position == 0 || position > target.size()) {
      return target;
    }

    List<T> newSequence = new ArrayList<>(target);
    newSequence.remove(position - 1);
    return newSequence;
  }
}
