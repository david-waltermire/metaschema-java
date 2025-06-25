/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.impl;

import gov.nist.secauto.metaschema.core.metapath.ContextAbsentDynamicMetapathException;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.CalledContext;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.IItemVisitor;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * This abstract implementation provides common functionality shared by all
 * functions.
 */
public abstract class AbstractFunction implements IFunction {
  @NonNull
  private final IEnhancedQName qname;
  @NonNull
  private final List<IArgument> arguments;

  /**
   * Construct a new function using the provided name and namespace, used together
   * to form the function's qualified name, and the provided arguments.
   * <p>
   * This constructor is equivalent to calling:
   *
   * <pre>
   * {@code
   * String name = ...;
   * String namespace = ...;
   * List<IArgument> arguments = ...;
   * new AbstractFunction(IEnhancedQName.of(namespace, name), arguments);
   * }
   * </pre>
   *
   * @param name
   *          the function's name
   * @param namespace
   *          the function's namespace
   * @param arguments
   *          the function's arguments
   */
  protected AbstractFunction(
      @NonNull String name,
      @NonNull String namespace,
      @NonNull List<IArgument> arguments) {
    this(IEnhancedQName.of(namespace, name), arguments);
  }

  /**
   * Construct a new function using the provided qualified name and arguments.
   *
   * @param qname
   *          the function's qualified name
   * @param arguments
   *          the function's arguments
   */
  protected AbstractFunction(
      @NonNull IEnhancedQName qname,
      @NonNull List<IArgument> arguments) {
    this.qname = qname;
    this.arguments = arguments;
  }

  @Override
  public IEnhancedQName getQName() {
    return qname;
  }

  @Override
  public int arity() {
    return arguments.size();
  }

  @Override
  public List<IArgument> getArguments() {
    return arguments;
  }

  @Override
  public Object getValue() {
    // never a value
    return null;
  }

  @Override
  public void accept(IItemVisitor visitor) {
    visitor.visit(this);
  }

  /**
   * Converts arguments in an attempt to align with the function's signature.
   *
   * @param function
   *          the function
   * @param parameters
   *          the argument parameters
   * @param dynamicContext
   *          the dynamic evaluation context
   * @return a new unmodifiable list containing the converted arguments
   */
  @NonNull
  public static List<ISequence<?>> convertArguments(
      @NonNull IFunction function,
      @NonNull List<? extends ISequence<?>> parameters,
      @NonNull DynamicContext dynamicContext) {
    List<ISequence<?>> retval = new ArrayList<>(parameters.size());
    Iterator<IArgument> argumentIterator = function.getArguments().iterator();
    IArgument argument = null;
    for (ISequence<?> parameter : parameters) {
      if (argumentIterator.hasNext()) {
        argument = argumentIterator.next();
      } else if (!function.isArityUnbounded()) {
        throw new InvalidTypeMetapathException(
            function,
            String.format("Argument signature doesn't match '%s'.", function.toSignature()));
      }

      assert argument != null;
      assert parameter != null;

      retval.add(convertArgument(argument, parameter, dynamicContext));
    }
    return CollectionUtil.unmodifiableList(retval);
  }

  @NonNull
  private static ISequence<?> convertArgument(
      @NonNull IArgument argument,
      @NonNull ISequence<?> parameter,
      @NonNull DynamicContext dynamicContext) {
    ISequenceType sequenceType = argument.getSequenceType();

    // apply occurrence
    ISequence<?> result = sequenceType.getOccurrence().getSequenceHandler().handle(parameter);

    // apply function conversion and type promotion to the parameter
    if (!result.isEmpty()) {
      IItemType type = sequenceType.getType();
      // this is not required to be an empty sequence
      result = convertSequence(argument, result, type, dynamicContext);
    }

    // verify resulting values
    return sequenceType.test(result);
  }

  /**
   * Based on XPath 3.1
   * <a href="https://www.w3.org/TR/xpath-31/#dt-function-conversion">function
   * conversion</a> rules.
   *
   * @param argument
   *          the function argument signature details
   * @param sequence
   *          the sequence to convert
   * @param requiredSequenceType
   *          the expected item type for the sequence
   * @param dynamicContext
   *          the dynamic evaluation context
   * @return the converted sequence
   */
  @NonNull
  protected static ISequence<?> convertSequence(
      @NonNull IArgument argument,
      @NonNull ISequence<?> sequence,
      @NonNull IItemType requiredSequenceType,
      @NonNull DynamicContext dynamicContext) {
    Class<? extends IItem> requiredSequenceTypeClass = requiredSequenceType.getItemClass();

    Stream<? extends IItem> stream = sequence.safeStream();

    if (IAnyAtomicItem.class.isAssignableFrom(requiredSequenceTypeClass)) {
      Stream<? extends IAnyAtomicItem> atomicStream = stream.flatMap(IItem::atomize);

      // if (IUntypedAtomicItem.class.isInstance(item)) {
      // // TODO: apply cast to atomic type
      // }

      if (IStringItem.class.equals(requiredSequenceTypeClass)) {
        // promote URIs to strings if a string is required
        atomicStream = atomicStream.map(item -> IAnyUriItem.class.isInstance(item) ? IStringItem.cast(item) : item);
      }

      stream = atomicStream;
    }

    stream = stream.peek(item -> {
      if (!requiredSequenceTypeClass.isInstance(item)) {
        throw new InvalidTypeMetapathException(
            item,
            String.format("The type '%s' is not a subtype of '%s'",
                item.getClass().getName(),
                requiredSequenceTypeClass.getName()));
      }
    });
    assert stream != null;

    return ISequence.of(stream);
  }

  @Nullable
  private IItem getContextItem(@NonNull ISequence<?> focus) {
    return isFocusDependent()
        ? focus.getFirstItem(true)
        : null;
  }

  @Override
  public ISequence<?> execute(
      @NonNull List<? extends ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      @NonNull ISequence<?> focus) {

    try {
      IItem contextItem = getContextItem(focus);
      if (isFocusDependent() && contextItem == null) {
        throw new ContextAbsentDynamicMetapathException("The context item is empty.");
      }

      List<ISequence<?>> convertedArguments = convertArguments(this, arguments, dynamicContext);

      CalledContext callingContext = null;
      ISequence<?> result = null;
      if (isDeterministic()) {
        // check cache
        callingContext = new CalledContext(this, convertedArguments, contextItem);
        // TODO: implement something like computeIfAbsent
        // attempt to get the result from the cache
        result = dynamicContext.getCachedResult(callingContext);
      }

      if (result == null) {
        result = executeInternal(convertedArguments, dynamicContext, contextItem);

        if (callingContext != null) {
          // add result to cache
          dynamicContext.cacheResult(
              callingContext,
              // ensure the result sequence is list backed
              result.reusable());
        }
      }

      // logger.info(String.format("Executed function '%s' with arguments '%s'
      // producing result '%s'",
      // toSignature(), convertedArguments.toString(), result.asList().toString()));
      return result;
    } catch (MetapathException ex) {
      ex.registerEvaluationContext(dynamicContext);
      throw ex;
    }
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
   *          the current focus
   * @return a sequence containing the result of the execution
   * @throws MetapathException
   *           if an error occurred while executing the function
   */
  @NonNull
  protected abstract ISequence<?> executeInternal(
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      @Nullable IItem focus);

  @Override
  public int hashCode() {
    return Objects.hash(getQName(), getArguments());
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true; // NOPMD - readability
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false; // NOPMD - readability
    }
    AbstractFunction other = (AbstractFunction) obj;
    return Objects.equals(getQName(), other.getQName())
        && Objects.equals(getArguments(), other.getArguments());
  }

  @Override
  public String toString() {
    return toSignature();
  }
}
