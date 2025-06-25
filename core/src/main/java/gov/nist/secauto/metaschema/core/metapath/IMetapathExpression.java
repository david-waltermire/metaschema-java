/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import gov.nist.secauto.metaschema.core.metapath.function.library.FnBoolean;
import gov.nist.secauto.metaschema.core.metapath.impl.LazyCompilationMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.impl.MetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.math.BigDecimal;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Supports compiling and executing Metapath expressions.
 */
public interface IMetapathExpression extends IExpression {

  /**
   * Identifies the expected type for a Metapath evaluation result.
   */
  enum ResultType {
    /**
     * The result is expected to be a {@link BigDecimal} value.
     */
    NUMBER(BigDecimal.class, sequence -> sequence.toNumeric(true)),
    /**
     * The result is expected to be a {@link String} value.
     */
    STRING(String.class, sequence -> {
      IAnyAtomicItem item = ISequence.of(sequence.atomize()).getFirstItem(true);
      return item == null ? "" : item.asString();
    }),
    /**
     * The result is expected to be a {@link Boolean} value.
     */
    BOOLEAN(Boolean.class, sequence -> FnBoolean.fnBoolean(sequence).toBoolean()),
    /**
     * The result is expected to be an {@link IItem} value.
     */
    ITEM(IItem.class, sequence -> sequence.getFirstItem(true));

    @NonNull
    private final Class<?> clazz;
    private final ConversionFunction converter;

    ResultType(@NonNull Class<?> clazz, @NonNull ConversionFunction converter) {
      this.clazz = clazz;
      this.converter = converter;
    }

    /**
     * Get the expected class for the result type.
     *
     * @return the expected class
     *
     */
    @NonNull
    public Class<?> expectedClass() {
      return clazz;
    }

    /**
     * Convert the provided sequence to the expected type.
     *
     * @param <T>
     *          the Java type of the expected return value
     * @param sequence
     *          the Metapath result sequence to convert
     * @return the converted sequence as the expected type
     * @throws TypeMetapathException
     *           if the provided sequence is incompatible with the expected result
     *           type
     */
    // TODO: trace exceptions thrown to ensure the Javadoc matches; should be static
    // type error
    @Nullable
    public <T> T convert(@NonNull ISequence<?> sequence) {
      try {
        return ObjectUtils.asNullableType(converter.convert(sequence));
      } catch (ClassCastException ex) {
        throw new InvalidTypeMetapathException(
            null,
            String.format("Unable to cast type '%s' to expected result type '%s'.",
                expectedClass().getName(),
                name()),
            ex);
      }
    }

    @FunctionalInterface
    interface ConversionFunction {
      @Nullable
      Object convert(@NonNull ISequence<?> sequence);
    }
  }

  /**
   * Get the Metapath expression identifying the current context node.
   *
   * @return the context expression
   */
  @NonNull
  static IMetapathExpression contextNode() {
    return MetapathExpression.CONTEXT_METAPATH;
  }

  /**
   * Compile a Metapath expression string.
   *
   * @param path
   *          the metapath expression
   * @return the compiled expression object
   * @throws InvalidMetapathGrammarException
   *           if an error occurred while compiling the Metapath expression
   */
  @NonNull
  static IMetapathExpression compile(@NonNull String path) {
    return compile(path, StaticContext.instance());
  }

  /**
   * Compiles a Metapath expression string using the provided static context.
   *
   * @param path
   *          the metapath expression
   * @param staticContext
   *          the static evaluation context
   * @return the compiled expression object
   * @throws InvalidMetapathGrammarException
   *           if an error occurred while compiling the Metapath expression
   */
  @NonNull
  static IMetapathExpression compile(@NonNull String path, @NonNull StaticContext staticContext) {
    return MetapathExpression.compile(path, staticContext);
  }

  /**
   * Gets a new Metapath expression that is compiled on use.
   * <p>
   * Lazy compilation may cause additional {@link MetapathException} errors at
   * evaluation time, since compilation errors are not raised until evaluation.
   *
   * @param path
   *          the metapath expression
   * @param staticContext
   *          the static evaluation context
   * @return the expression object
   */
  @NonNull
  static IMetapathExpression lazyCompile(@NonNull String path, @NonNull StaticContext staticContext) {
    return new LazyCompilationMetapathExpression(path, staticContext);
  }

  /**
   * Get the original Metapath expression as a string.
   *
   * @return the expression
   */
  @Override
  @NonNull
  String getPath();

  /**
   * Get the static context used to compile this Metapath.
   *
   * @return the static context
   */
  @NonNull
  StaticContext getStaticContext();

  /**
   * Evaluate this Metapath expression without a specific focus. The required
   * result type will be determined by the {@code resultType} argument.
   *
   * @param <T>
   *          the expected result type
   * @param resultType
   *          the type of result to produce
   * @return the converted result
   * @throws TypeMetapathException
   *           if the provided sequence is incompatible with the requested result
   *           type
   * @throws MetapathException
   *           if an error occurred during evaluation
   * @see ResultType#convert(ISequence)
   */
  @Nullable
  default <T> T evaluateAs(@NonNull ResultType resultType) {
    return evaluateAs(null, resultType);
  }

  /**
   * Evaluate this Metapath expression using the provided {@code focus} as the
   * initial evaluation context. The required result type will be determined by
   * the {@code resultType} argument.
   *
   * @param <T>
   *          the expected result type
   * @param focus
   *          the focus of the expression
   * @param resultType
   *          the type of result to produce
   * @return the converted result
   * @throws TypeMetapathException
   *           if the provided sequence is incompatible with the requested result
   *           type
   * @throws MetapathException
   *           if an error occurred during evaluation
   * @see ResultType#convert(ISequence)
   */
  @Nullable
  default <T> T evaluateAs(
      @Nullable IItem focus,
      @NonNull ResultType resultType) {
    ISequence<?> result = evaluate(focus);
    return resultType.convert(result);
  }

  /**
   * Evaluate this Metapath expression using the provided {@code focus} as the
   * initial evaluation context. The specific result type will be determined by
   * the {@code resultType} argument.
   * <p>
   * This variant allow for reuse of a provided {@code dynamicContext}.
   *
   * @param <T>
   *          the expected result type
   * @param focus
   *          the outer focus of the expression
   * @param resultType
   *          the type of result to produce
   * @param dynamicContext
   *          the dynamic context to use for evaluation
   * @return the converted result
   * @throws TypeMetapathException
   *           if the provided sequence is incompatible with the requested result
   *           type
   * @throws MetapathException
   *           if an error occurred during evaluation
   * @see ResultType#convert(ISequence)
   */
  @Nullable
  default <T> T evaluateAs(
      @Nullable IItem focus,
      @NonNull ResultType resultType,
      @NonNull DynamicContext dynamicContext) {
    ISequence<?> result = evaluate(focus, dynamicContext);
    return resultType.convert(result);
  }

  /**
   * Evaluate this Metapath expression without a specific focus.
   *
   * @param <T>
   *          the type of items contained in the resulting sequence
   * @return a sequence of Metapath items representing the result of the
   *         evaluation
   * @throws MetapathException
   *           if an error occurred during evaluation
   */
  @NonNull
  default <T extends IItem> ISequence<T> evaluate() {
    return evaluate((IItem) null);
  }

  /**
   * Evaluate this Metapath expression using the provided {@code focus} as the
   * initial evaluation context.
   *
   * @param <T>
   *          the type of items contained in the resulting sequence
   * @param focus
   *          the outer focus of the expression
   * @return a sequence of Metapath items representing the result of the
   *         evaluation
   * @throws MetapathException
   *           if an error occurred during evaluation
   */
  @NonNull
  default <T extends IItem> ISequence<T> evaluate(
      @Nullable IItem focus) {
    return evaluate(focus, new DynamicContext(getStaticContext()));
  }

  /**
   * Evaluate this Metapath expression using the provided {@code focus} as the
   * initial evaluation context.
   * <p>
   * This variant allow for reuse of a provided {@code dynamicContext}.
   *
   * @param <T>
   *          the type of items contained in the resulting sequence
   * @param focus
   *          the outer focus of the expression
   * @param dynamicContext
   *          the dynamic context to use for evaluation
   * @return a sequence of Metapath items representing the result of the
   *         evaluation
   * @throws MetapathException
   *           if an error occurred during evaluation
   */
  @NonNull
  <T extends IItem> ISequence<T> evaluate(
      @Nullable IItem focus,
      @NonNull DynamicContext dynamicContext);

}
