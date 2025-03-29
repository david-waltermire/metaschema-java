/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.impl.AbstractFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides a concrete implementation of a function call executor.
 */
public class DefaultFunction
    extends AbstractFunction {
  // private static final Logger logger =
  // LogManager.getLogger(AbstractFunction.class);

  @NonNull
  private final Set<FunctionProperty> properties;
  @NonNull
  private final ISequenceType result;
  @NonNull
  private final IFunctionExecutor handler;

  /**
   * Construct a new function signature.
   *
   * @param name
   *          the name of the function
   * @param properties
   *          the characteristics of the function
   * @param arguments
   *          the argument signatures or an empty list
   * @param result
   *          the type of the result
   * @param handler
   *          the handler to call to execute the function
   */
  @SuppressWarnings({ "null", "PMD.LooseCoupling" })
  DefaultFunction(
      @NonNull String name,
      @NonNull String namespace,
      @NonNull EnumSet<FunctionProperty> properties,
      @NonNull List<IArgument> arguments,
      @NonNull ISequenceType result,
      @NonNull IFunctionExecutor handler) {
    super(name, namespace, arguments);
    this.properties = Collections.unmodifiableSet(properties);
    this.result = result;
    this.handler = handler;
  }

  @Override
  public Set<FunctionProperty> getProperties() {
    return properties;
  }

  @Override
  public ISequenceType getResult() {
    return result;
  }

  @Override
  public boolean isNamedFunction() {
    return true;
  }

  /**
   * Execute the provided function using the provided arguments, dynamic context,
   * and focus.
   *
   * @param arguments
   *          the function arguments
   * @param dynamicContext
   *          the dynamic evaluation context
   * @param focus
   *          the current focus item in the evaluation context. This represents
   *          the context item for anonymous function evaluation. May be null for
   *          functions that don't require context item access.
   * @return a sequence containing the result of the execution
   * @throws MetapathException
   *           if an error occurred while executing the function
   */
  @Override
  @NonNull
  protected ISequence<?> executeInternal(
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      @Nullable IItem focus) {
    return handler.execute(this, arguments, dynamicContext, focus);
  }
}
