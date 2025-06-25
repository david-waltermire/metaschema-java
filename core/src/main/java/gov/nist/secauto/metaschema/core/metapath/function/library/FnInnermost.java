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
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * /** Implements <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-innermost">fn:innermost</a>
 * functions.
 */
public final class FnInnermost {
  @NonNull
  private static final String NAME = "innermost";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusDependent()
      .argument(IArgument.builder()
          .name("nodes")
          .type(INodeItem.type())
          .zeroOrMore()
          .build())
      .returnType(INodeItem.type())
      .returnZeroOrMore()
      .functionHandler(FnInnermost::execute)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<? extends INodeItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    ISequence<INodeItem> nodes = arguments.get(0).ofType(INodeItem.type());
    return ISequence.of(fnInnermost(nodes));
  }

  /**
   * Get every node within the provided list that is not an ancestor of another
   * member of the provided list.
   * <p>
   * The nodes are returned in document order with duplicates eliminated.
   * <p>
   * Based on the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-innermost">fn:innermost</a>
   * function.
   *
   * @param arg
   *          the node items check
   * @return the nodes that are not an ancestor of another member of the provided
   *         list
   */
  @NonNull
  public static Stream<? extends INodeItem> fnInnermost(@NonNull List<? extends INodeItem> arg) {
    Set<? extends INodeItem> ancestors = arg.stream()
        .distinct()
        .flatMap(INodeItem::ancestor)
        .collect(Collectors.toSet());

    return ObjectUtils.notNull(arg.stream()
        .distinct()
        .filter(node -> !ancestors.contains(node)));
  }

  private FnInnermost() {
    // disable construction
  }
}
