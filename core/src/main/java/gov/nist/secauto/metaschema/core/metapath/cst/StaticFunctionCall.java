/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Executes a function call based on the provided function and multiple argument
 * expressions that are used to determine the function arguments.
 * <p>
 * This class handles static function calls where the name of the function is
 * known during static analysis (the parsing phase), as opposed to dynamic or
 * anonymous function calls where the name is not available or known until
 * execution.
 * <p>
 * Static functions are resolved during the parsing phase and must exist in the
 * function registry.
 */
public class StaticFunctionCall
    extends AbstractExpression {
  @NonNull
  private final Lazy<IFunction> functionSupplier;
  @NonNull
  private final List<IExpression> arguments;

  /**
   * Construct a new function call expression.
   *
   * @param text
   *          the parsed text of the expression
   * @param functionSupplier
   *          the function supplier, which is used to lazy fetch the function
   *          allowing the containing Metapaths to parse even if a function does
   *          not exist during the parsing phase.
   * @param arguments
   *          the expressions used to provide arguments to the function call
   */
  public StaticFunctionCall(
      @NonNull String text,
      @NonNull Supplier<IFunction> functionSupplier,
      @NonNull List<IExpression> arguments) {
    super(text);
    this.functionSupplier = ObjectUtils.notNull(Lazy.of(functionSupplier));
    this.arguments = arguments;
  }

  /**
   * Retrieve the associated function.
   *
   * @return the function or {@code null} if no function matched the defined name
   *         and arguments
   * @throws StaticMetapathException
   *           if the function was not found
   */
  @NonNull
  public IFunction getFunction() {
    IFunction function = functionSupplier.get();
    if (function == null) {
      throw new StaticMetapathException(
          StaticMetapathException.NO_FUNCTION_MATCH,
          String.format(
              "No matching function found for the given name and arguments"));
    }
    return function;
  }

  @Override
  public List<IExpression> getChildren() {
    return arguments;
  }

  @Override
  public Class<? extends IItem> getBaseResultType() {
    return getFunction().getResult().getType().getItemClass();
  }

  @SuppressWarnings("null")
  @Override
  public String toCSTString() {
    return String.format("%s[name=%s, arity=%d]", getClass().getName(), getFunction().getQName(),
        getFunction().arity());
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitStaticFunctionCall(this, context);
  }

  @Override
  protected ISequence<?> evaluate(DynamicContext dynamicContext, ISequence<?> focus) {
    List<ISequence<?>> arguments = ObjectUtils.notNull(this.arguments.stream()
        .map(expression -> expression.accept(dynamicContext, focus).contentsAsSequence())
        .collect(Collectors.toList()));

    IFunction function = getFunction();
    return function.execute(arguments, dynamicContext, focus);
  }
}
