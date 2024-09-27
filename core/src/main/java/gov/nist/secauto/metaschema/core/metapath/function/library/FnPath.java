/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.format.IPathFormatter;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Since a node doesn't have a base URI in Metaschema, this is an alias for the
 * document-uri function.
 */
public final class FnPath {

  @NonNull
  static final IFunction SIGNATURE_NO_ARG = IFunction.builder()
      .name("path")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextDependent()
      .focusDependent()
      .returnType(IStringItem.class)
      .returnZeroOrOne()
      .functionHandler(FnPath::executeNoArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name("path")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("arg1")
          .type(INodeItem.class)
          .zeroOrOne()
          .build())
      .returnType(IStringItem.class)
      .returnZeroOrOne()
      .functionHandler(FnPath::executeOneArg)
      .build();

  private FnPath() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeNoArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    INodeItem item = FunctionUtils.requireTypeOrNull(INodeItem.class, focus);

    ISequence<IStringItem> retval;
    if (item == null) {
      retval = ISequence.empty();
    } else {
      retval = ISequence.of(IStringItem.valueOf(item.toPath(IPathFormatter.METAPATH_PATH_FORMATER)));
    }
    return retval;
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IStringItem> executeOneArg(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    return fnPath(ObjectUtils.requireNonNull(arguments.get(0)));
  }

  /**
   * An implementation of XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-path">fn:path</a>.
   *
   * @param sequence
   *          a Metapath sequence containing an item to get the Metapath for
   * @return a sequence containing the generated Metapath
   */
  @NonNull
  public static ISequence<IStringItem> fnPath(@NonNull ISequence<?> sequence) {
    IItem item = sequence.getFirstItem(true);

    ISequence<IStringItem> retval;
    if (item == null) {
      retval = ISequence.empty();
    } else {
      try {
        retval = ISequence.of(fnPath((INodeItem) item));
      } catch (ClassCastException ex) {
        throw new InvalidTypeMetapathException(
            item,
            String.format("Expected a '%s', but received a '%s'",
                INodeItem.class.getName(),
                item.getClass().getName()),
            ex);
      }
    }
    return retval;
  }

  /**
   * Generates a Metapath for the provided item.
   *
   * @param item
   *          the item to get the Metapath for
   * @return the generated Metapath
   */
  @Nullable
  public static IStringItem fnPath(@Nullable INodeItem item) {
    return item == null ? null : IStringItem.valueOf(item.toPath(IPathFormatter.METAPATH_PATH_FORMATER));
  }
}
