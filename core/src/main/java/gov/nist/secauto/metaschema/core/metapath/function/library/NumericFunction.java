/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.IFunctionExecutor;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides a generic implementation of methods defined by <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#numeric-value-functions">XPath 3.1
 * Functions on numeric values</a>.
 */
public final class NumericFunction implements IFunctionExecutor {

  @NonNull
  private final INumericExecutor executor;

  @NonNull
  static IFunction signature(@NonNull String namespace, @NonNull String name, @NonNull INumericExecutor executor) {
    return IFunction.builder()
        .name(name)
        .namespace(namespace)
        .deterministic()
        .contextIndependent()
        .focusIndependent()
        .argument(IArgument.builder()
            .name("arg1")
            .type(INumericItem.type())
            .zeroOrOne()
            .build())
        .returnType(INumericItem.type())
        .returnZeroOrOne()
        .functionHandler(newFunctionHandler(executor))
        .build();
  }

  @NonNull
  static IFunction signature(@NonNull QName qname, @NonNull INumericExecutor executor) {
    return signature(
        ObjectUtils.requireNonNull(qname.getNamespaceURI(), "the namespace URI must not be null"),
        ObjectUtils.requireNonNull(qname.getLocalPart(), "the localpart must not be null"),
        executor);
  }

  @NonNull
  static NumericFunction newFunctionHandler(@NonNull INumericExecutor executor) {
    return new NumericFunction(executor);
  }

  private NumericFunction(@NonNull INumericExecutor executor) {
    this.executor = executor;
  }

  @Override
  public ISequence<INumericItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    ISequence<INumericItem> sequence = arguments.get(0).ofType(INumericItem.type());
    if (sequence.isEmpty()) {
      return ISequence.empty(); // NOPMD - readability
    }

    INumericItem item = sequence.getFirstItem(true);
    if (item == null) {
      return ISequence.empty(); // NOPMD - readability
    }

    INumericItem result = executor.execute(item);
    return ISequence.of(result);
  }

  /**
   * Implementations of this interface are used to execute a numeric opertaion on
   * the provided item.
   */
  @FunctionalInterface
  public interface INumericExecutor {
    /**
     * Perform the execution using the provided {@code item}.
     *
     * @param item
     *          the item to operate on
     * @return the numeric result from the execution
     */
    @NonNull
    INumericItem execute(@NonNull INumericItem item);
  }
}
