/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.impl.AbstractFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Executes an unnamed function call based on a client provided Metapath
 * expression that is declared inline within a Metapath expression.
 */
public class AnonymousFunctionCall
    extends AbstractExpression {
  private final AnonymousFunction function;

  /**
   * Construct a new function call expression.
   *
   * @param text
   *          the parsed text of the expression
   * @param arguments
   *          the parameter declarations for the function call
   * @param result
   *          the expected result of the function call
   * @param body
   *          the Metapath expression that implements the logic of the function
   */
  public AnonymousFunctionCall(
      @NonNull String text,
      @NonNull List<IArgument> arguments,
      @NonNull ISequenceType result,
      @NonNull IExpression body) {
    super(text);
    this.function = new AnonymousFunction(arguments, result, body);
  }

  /**
   * Get the function associated with this Metapath expression.
   *
   * @return the function
   */
  protected AnonymousFunction getFunction() {
    return function;
  }

  @Override
  public List<IExpression> getChildren() {
    return ObjectUtils.notNull(List.of(getFunction().getBody()));
  }

  @Override
  public Class<? extends IItem> getBaseResultType() {
    return IFunction.class;
  }

  @Override
  public <RESULT, CONTEXT> RESULT accept(IExpressionVisitor<RESULT, CONTEXT> visitor, CONTEXT context) {
    return visitor.visitAnonymousFunctionCall(this, context);
  }

  @Override
  protected ISequence<?> evaluate(DynamicContext dynamicContext, ISequence<?> focus) {
    return ISequence.of(getFunction());
  }

  @SuppressWarnings("null")
  @Override
  public String toCSTString() {
    IFunction function = getFunction();
    return String.format("%s[arguments=%s,return=%s]",
        getClass().getName(),
        function.getArguments(),
        function.getResult().toSignature());
  }

  private static final class AnonymousFunction
      extends AbstractFunction {
    @NonNull
    private static final Set<FunctionProperty> PROPERTIES = ObjectUtils.notNull(EnumSet.of(
        FunctionProperty.DETERMINISTIC));
    @NonNull
    private final ISequenceType result;
    @NonNull
    private final IExpression body;

    public AnonymousFunction(
        @NonNull List<IArgument> arguments,
        @NonNull ISequenceType result,
        @NonNull IExpression body) {
      super("(anonymous)-" + UUID.randomUUID().toString(), "", arguments);
      this.result = result;
      this.body = body;
    }

    @Override
    public ISequenceType getResult() {
      return result;
    }

    @NonNull
    protected IExpression getBody() {
      return body;
    }

    @Override
    public Set<FunctionProperty> getProperties() {
      return PROPERTIES;
    }

    @Override
    public boolean isNamedFunction() {
      // these functions are anonymous
      return false;
    }

    @Override
    @NonNull
    protected ISequence<?> executeInternal(
        @NonNull List<ISequence<?>> arguments,
        @NonNull DynamicContext dynamicContext,
        @Nullable IItem focus) {

      DynamicContext subContext = dynamicContext.subContext();
      if (arguments.size() != getArguments().size()) {
        throw new IllegalArgumentException("Number of arguments does not match the number of parameters.");
      }

      Iterator<? extends ISequence<?>> args = arguments.iterator();
      Iterator<IArgument> params = getArguments().iterator();
      while (args.hasNext() && params.hasNext()) {
        ISequence<?> sequence = args.next();
        IArgument param = params.next();

        subContext.bindVariableValue(param.getName(), ObjectUtils.notNull(sequence));
      }

      // the focus is not present according to
      // https://www.w3.org/TR/xpath-31/#id-eval-function-call
      // paragraph 5.b.ii
      return body.accept(subContext, ISequence.empty());
    }
  }
}
