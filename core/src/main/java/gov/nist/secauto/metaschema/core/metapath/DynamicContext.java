/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import com.github.benmanes.caffeine.cache.Caffeine;

import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.metapath.function.CalledContext;
import gov.nist.secauto.metaschema.core.metapath.function.DateTimeFunctionException;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction.FunctionProperty;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.model.IUriResolver;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

// TODO: add support for in-scope namespaces
/**
 * The implementation of a Metapath
 * <a href="https://www.w3.org/TR/xpath-31/#eval_context">dynamic context</a>.
 */
public class DynamicContext {

  @NonNull
  private final Map<Integer, ISequence<?>> letVariableMap;
  @NonNull
  private final SharedState sharedState;

  /**
   * Construct a new dynamic context with a default static context.
   */
  public DynamicContext() {
    this(StaticContext.instance());
  }

  /**
   * Construct a new Metapath dynamic context using the provided static context.
   *
   * @param staticContext
   *          the Metapath static context
   */
  public DynamicContext(@NonNull StaticContext staticContext) {
    this.letVariableMap = new ConcurrentHashMap<>();
    this.sharedState = new SharedState(staticContext);
  }

  private DynamicContext(@NonNull DynamicContext context) {
    this.letVariableMap = new ConcurrentHashMap<>(context.letVariableMap);
    this.sharedState = context.sharedState;
  }

  private static class SharedState {
    @NonNull
    private final StaticContext staticContext;
    @NonNull
    private final ZonedDateTime currentDateTime;
    @NonNull
    private final Map<URI, IDocumentNodeItem> availableDocuments;
    @NonNull
    private final Map<CalledContext, ISequence<?>> functionResultCache;
    @Nullable
    private CachingLoader documentLoader;
    @NonNull
    private final IMutableConfiguration<MetapathEvaluationFeature<?>> configuration;
    @NonNull
    private final Deque<IExpression> executionStack = new ArrayDeque<>();
    @NonNull
    private ZoneId implicitTimeZone;

    public SharedState(@NonNull StaticContext staticContext) {
      this.staticContext = staticContext;

      Clock clock = Clock.systemDefaultZone();

      this.implicitTimeZone = ObjectUtils.notNull(clock.getZone());

      this.currentDateTime = ObjectUtils.notNull(ZonedDateTime.now(clock));
      this.availableDocuments = new HashMap<>();
      this.functionResultCache = ObjectUtils.notNull(Caffeine.newBuilder()
          .maximumSize(5000)
          .expireAfterAccess(10, TimeUnit.MINUTES)
          .<CalledContext, ISequence<?>>build().asMap());
      this.configuration = new DefaultConfiguration<>();
      this.configuration.enableFeature(MetapathEvaluationFeature.METAPATH_EVALUATE_PREDICATES);
    }
  }

  /**
   * Generate a new dynamic context that is a copy of this dynamic context.
   * <p>
   * This method can be used to create a new sub-context where changes can be made
   * without affecting this context. This is useful for setting information that
   * is only used in a limited evaluation sub-scope, such as for handling variable
   * assignment.
   *
   * @return a new dynamic context
   */
  @NonNull
  public DynamicContext subContext() {
    return new DynamicContext(this);
  }

  /**
   * Get the static context associated with this dynamic context.
   *
   * @return the associated static context
   */
  @NonNull
  public StaticContext getStaticContext() {
    return sharedState.staticContext;
  }

  /**
   * Get the default time zone used for evaluation.
   *
   * @return the time zone identifier object
   */
  @NonNull
  public ZoneId getImplicitTimeZone() {
    return sharedState.implicitTimeZone;
  }

  /**
   * Get the default time zone used for evaluation.
   *
   * @return the time zone identifier object
   */
  @NonNull
  public IDayTimeDurationItem getImplicitTimeZoneAsDayTimeDuration() {
    LocalDateTime referenceDateTime = MetapathConstants.REFERENCE_DATE_TIME.asLocalDateTime();
    ZonedDateTime reference = referenceDateTime.atZone(getImplicitTimeZone());
    ZonedDateTime referenceZ = referenceDateTime.atZone(ZoneOffset.UTC);

    return IDayTimeDurationItem.valueOf(ObjectUtils.notNull(
        Duration.between(
            reference,
            referenceZ)));
  }

  /**
   * Set the implicit timezone to the provided value.
   * <p>
   * Note: This value should only be adjusted when the context is first created.
   * Once the context is used, this value is expected to be stable.
   *
   * @param timezone
   *          the timezone to use
   */
  public void setImplicitTimeZone(@NonNull ZoneId timezone) {
    sharedState.implicitTimeZone = timezone;
  }

  /**
   * Set the implicit timezone to the provided value.
   * <p>
   * Note: This value should only be adjusted when the context is first created.
   * Once the context is used, this value is expected to be stable.
   *
   * @param offset
   *          the offset which must be &gt;= -PT14H and &lt;= PT13H
   * @throws DateTimeFunctionException
   *           with the code
   *           {@link DateTimeFunctionException#INVALID_TIME_ZONE_VALUE_ERROR} if
   *           the offset is &lt; -PT14H or &gt; PT14H
   */
  public void setImplicitTimeZone(@NonNull IDayTimeDurationItem offset) {
    setImplicitTimeZone(offset.asZoneOffset());
  }

  /**
   * Get the current date and time.
   *
   * @return the current date and time
   */
  @NonNull
  public ZonedDateTime getCurrentDateTime() {
    return sharedState.currentDateTime;
  }

  /**
   * Get the mapping of loaded documents from the document URI to the document
   * node.
   *
   * @return the map of document URIs to document nodes
   */
  @SuppressWarnings("null")
  @NonNull
  public Map<URI, IDocumentNodeItem> getAvailableDocuments() {
    return Collections.unmodifiableMap(sharedState.availableDocuments);
  }

  /**
   * Get the document loader assigned to this dynamic context.
   *
   * @return the loader
   * @throws ContextAbsentDynamicMetapathException
   *           if a document loader is not configured for this dynamic context
   */
  @NonNull
  public IDocumentLoader getDocumentLoader() {
    IDocumentLoader retval = sharedState.documentLoader;
    if (retval == null) {
      throw new UnsupportedOperationException(
          "No document loader configured for the dynamic context. Use setDocumentLoader(loader) to confgure one.");
    }
    return retval;
  }

  /**
   * Assign a document loader to this dynamic context.
   *
   * @param documentLoader
   *          the document loader to assign
   */
  public void setDocumentLoader(@NonNull IDocumentLoader documentLoader) {
    this.sharedState.documentLoader = new CachingLoader(documentLoader);
  }

  /**
   * Get the cached function call result for evaluating a function that has the
   * property {@link FunctionProperty#DETERMINISTIC}.
   *
   * @param callingContext
   *          the function calling context information that distinguishes the call
   *          from any other call
   * @return the cached result sequence for the function call
   */
  @Nullable
  public ISequence<?> getCachedResult(@NonNull CalledContext callingContext) {
    return sharedState.functionResultCache.get(callingContext);
  }

  /**
   * Cache a function call result for a that has the property
   * {@link FunctionProperty#DETERMINISTIC}.
   *
   * @param callingContext
   *          the calling context information that distinguishes the call from any
   *          other call
   * @param result
   *          the function call result
   */
  public void cacheResult(@NonNull CalledContext callingContext, @NonNull ISequence<?> result) {
    ISequence<?> old = sharedState.functionResultCache.put(callingContext, result);
    assert old == null;
  }

  /**
   * Used to disable the evaluation of predicate expressions during Metapath
   * evaluation.
   * <p>
   * This can be useful for determining the potential targets identified by a
   * Metapath expression as a partial evaluation, without evaluating that these
   * targets match the predicate.
   *
   * @return this dynamic context
   */
  @NonNull
  public DynamicContext disablePredicateEvaluation() {
    this.sharedState.configuration.disableFeature(MetapathEvaluationFeature.METAPATH_EVALUATE_PREDICATES);
    return this;
  }

  /**
   * Used to enable the evaluation of predicate expressions during Metapath
   * evaluation.
   * <p>
   * This is the default behavior if unchanged.
   *
   * @return this dynamic context
   */
  @NonNull
  public DynamicContext enablePredicateEvaluation() {
    this.sharedState.configuration.enableFeature(MetapathEvaluationFeature.METAPATH_EVALUATE_PREDICATES);
    return this;
  }

  /**
   * Get the Metapath evaluation configuration.
   *
   * @return the configuration
   */
  @NonNull
  public IConfiguration<MetapathEvaluationFeature<?>> getConfiguration() {
    return sharedState.configuration;
  }

  /**
   * Get the sequence value assigned to a let variable with the provided qualified
   * name.
   *
   * @param name
   *          the variable qualified name
   * @return the non-null variable value
   * @throws DynamicMetapathException
   *           of the variable has not been assigned or if the variable value is
   *           {@code null}
   */
  @NonNull
  public ISequence<?> getVariableValue(@NonNull IEnhancedQName name) {
    ISequence<?> retval = letVariableMap.get(name.getIndexPosition());
    if (retval == null) {
      throw new StaticMetapathException(
          StaticMetapathException.NOT_DEFINED,
          String.format("Variable '%s' not defined in the dynamic context.", name))
              .registerEvaluationContext(this);
    }
    return retval;
  }

  /**
   * Get the function with the provided name and arity.
   *
   * @param name
   *          the requested function's qualified name
   * @param arity
   *          the number of arguments in the requested function
   * @return the function
   * @throws StaticMetapathException
   *           with the code {@link StaticMetapathException#NO_FUNCTION_MATCH} if
   *           a matching function was not found
   */
  @NonNull
  public IFunction lookupFunction(@NonNull IEnhancedQName name, int arity) {
    return getStaticContext().lookupFunction(name, arity);
  }

  /**
   * Bind the variable {@code name} to the sequence {@code value}.
   *
   * @param name
   *          the name of the variable to bind
   * @param boundValue
   *          the value to bind to the variable
   * @return this dynamic context
   */
  @NonNull
  public DynamicContext bindVariableValue(@NonNull IEnhancedQName name, @NonNull ISequence<?> boundValue) {
    letVariableMap.put(name.getIndexPosition(), boundValue);
    return this;
  }

  /**
   * Push the current expression under evaluation to the execution queue.
   *
   * @param expression
   *          the expression to push
   */
  public void pushExecutionStack(@NonNull IExpression expression) {
    this.sharedState.executionStack.push(expression);
  }

  /**
   * Pop the expression that was under evaluation from the execution queue.
   *
   * @param expression
   *          the expected expression to be popped
   */
  public void popExecutionStack(@NonNull IExpression expression) {
    IExpression popped = this.sharedState.executionStack.pop();
    if (!expression.equals(popped)) {
      throw new IllegalStateException("Popped expression does not match expected expression");
    }
  }

  /**
   * Return a copy of the current execution stack.
   *
   * @return the execution stack
   */
  @NonNull
  public Deque<IExpression> getExecutionStack() {
    return new ArrayDeque<>(this.sharedState.executionStack);
  }

  /**
   * Provides a formatted stack trace.
   *
   * @return the formatted stack trace
   */
  @NonNull
  public String formatExecutionStackTrace() {
    return ObjectUtils.notNull(getExecutionStack().stream()
        .map(IExpression::toCSTString)
        .collect(Collectors.joining("\n-> ")));
  }

  private class CachingLoader implements IDocumentLoader {
    @NonNull
    private final IDocumentLoader proxy;

    public CachingLoader(@NonNull IDocumentLoader proxy) {
      this.proxy = proxy;
    }

    @Override
    public IUriResolver getUriResolver() {
      return new ContextUriResolver();
    }

    @Override
    public void setUriResolver(@NonNull IUriResolver resolver) {
      // we delegate to the document loader proxy, so the resolver should be set there
      throw new UnsupportedOperationException("Set the resolver on the proxy");
    }

    @NonNull
    protected IDocumentLoader getProxiedDocumentLoader() {
      return proxy;
    }

    @Override
    public IDocumentNodeItem loadAsNodeItem(URI uri) throws IOException {
      IDocumentNodeItem retval = sharedState.availableDocuments.get(uri);
      if (retval == null) {
        retval = getProxiedDocumentLoader().loadAsNodeItem(uri);
        sharedState.availableDocuments.put(uri, retval);
      }
      return retval;
    }

    public class ContextUriResolver implements IUriResolver {

      /**
       * {@inheritDoc}
       * <p>
       * This method first resolves the provided URI against the static context's base
       * URI.
       */
      @Override
      public URI resolve(URI uri) {
        URI baseUri = getStaticContext().getBaseUri();

        URI resolvedUri;
        if (baseUri == null) {
          resolvedUri = uri;
        } else {
          resolvedUri = ObjectUtils.notNull(baseUri.resolve(uri));
        }

        IUriResolver resolver = getProxiedDocumentLoader().getUriResolver();
        return resolver == null ? resolvedUri : resolver.resolve(resolvedUri);
      }
    }
  }
}
