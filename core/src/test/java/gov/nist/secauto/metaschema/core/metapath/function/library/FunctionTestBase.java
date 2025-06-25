/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ExpressionTestBase;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public class FunctionTestBase
    extends ExpressionTestBase {

  /**
   * Assert that the execution of the provided function and arguments produce the
   * desired results.
   *
   * @param function
   *          the function to test
   * @param expectedResult
   *          the expected result produced by the function
   * @param arguments
   *          the function arguments to use for evaluation
   */
  public static void assertFunctionResult(
      @NonNull IFunction function,
      @NonNull ISequence<?> expectedResult,
      @NonNull List<? extends ISequence<?>> arguments) {
    assertFunctionResult(function, null, expectedResult, arguments);
  }

  /**
   * Assert that the execution of the provided function and arguments produce the
   * desired results.
   *
   * @param function
   *          the function to test
   * @param focus
   *          the item focus to use for evaluation or {@code null} if there is no
   *          focus
   * @param expectedResult
   *          the expected result produced by the function
   * @param arguments
   *          the function arguments to use for evaluation
   */
  public static void assertFunctionResult(
      @NonNull IFunction function,
      @Nullable ISequence<?> focus,
      @NonNull ISequence<?> expectedResult,
      @NonNull List<? extends ISequence<?>> arguments) {
    ISequence<INumericItem> result = FunctionTestBase.executeFunction(
        function,
        newDynamicContext(),
        focus,
        arguments);

    assertAll(
        () -> assertEquals(expectedResult, result),
        () -> assertEquals(
            IItem.getTypes(expectedResult),
            IItem.getTypes(result)));

  }

  /**
   * Execute the provided function using the provided context, focus and
   * arguments.
   *
   * @param <R>
   *          the sequence result Java type
   * @param function
   *          the function to call
   * @param dynamicContext
   *          the dynamic evaluation context or {@code null} if the default should
   *          be used
   * @param focus
   *          the current focus or {@code null} if there is no focus
   * @param arguments
   *          the function arguments or an empty list if there are no arguments
   * @return the result of evaluating the function
   */
  @SuppressWarnings("unchecked")
  @NonNull
  public static <R extends IItem> ISequence<R> executeFunction(
      @NonNull IFunction function,
      @Nullable DynamicContext dynamicContext,
      @Nullable ISequence<?> focus,
      @NonNull List<? extends ISequence<?>> arguments) {

    DynamicContext context = dynamicContext == null ? new DynamicContext() : dynamicContext;
    ISequence<?> focusSeqence = function.isFocusDependent()
        ? focus == null ? ISequence.empty() : focus
        : ISequence.empty();
    return (ISequence<R>) function.execute(
        arguments,
        context,
        focusSeqence);
  }
}
