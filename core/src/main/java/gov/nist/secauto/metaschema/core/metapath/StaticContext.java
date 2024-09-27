/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import gov.nist.secauto.metaschema.core.metapath.EQNameUtils.PrefixToNamespaceResolver;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

// add support for default namespace
/**
 * The implementation of a Metapath
 * <a href="https://www.w3.org/TR/xpath-31/#static_context">static context</a>.
 */
public final class StaticContext {
  @NonNull
  private static final Map<String, URI> WELL_KNOWN_NAMESPACES;
  @NonNull
  private static final Map<String, String> WELL_KNOWN_URI_TO_PREFIX;

  static {
    Map<String, URI> knownNamespaces = new ConcurrentHashMap<>();
    knownNamespaces.put(
        MetapathConstants.PREFIX_METAPATH,
        MetapathConstants.NS_METAPATH);
    knownNamespaces.put(
        MetapathConstants.PREFIX_XML_SCHEMA,
        MetapathConstants.NS_XML_SCHEMA);
    knownNamespaces.put(
        MetapathConstants.PREFIX_XPATH_FUNCTIONS,
        MetapathConstants.NS_METAPATH_FUNCTIONS);
    knownNamespaces.put(
        MetapathConstants.PREFIX_XPATH_FUNCTIONS_MATH,
        MetapathConstants.NS_METAPATH_FUNCTIONS_MATH);
    knownNamespaces.put(
        MetapathConstants.PREFIX_XPATH_FUNCTIONS_ARRAY,
        MetapathConstants.NS_METAPATH_FUNCTIONS_ARRAY);
    knownNamespaces.put(
        MetapathConstants.PREFIX_XPATH_FUNCTIONS_MAP,
        MetapathConstants.NS_METAPATH_FUNCTIONS_MAP);
    WELL_KNOWN_NAMESPACES = CollectionUtil.unmodifiableMap(knownNamespaces);

    WELL_KNOWN_URI_TO_PREFIX = ObjectUtils.notNull(WELL_KNOWN_NAMESPACES.entrySet().stream()
        .collect(Collectors.toUnmodifiableMap(
            entry -> entry.getValue().toASCIIString(),
            Map.Entry::getKey,
            (v1, v2) -> v2)));
  }

  @Nullable
  private final URI baseUri;
  @NonNull
  private final Map<String, URI> knownNamespaces;
  @Nullable
  private final URI defaultModelNamespace;
  @Nullable
  private final URI defaultFunctionNamespace;
  private final boolean useWildcardWhenNamespaceNotDefaulted;

  /**
   * Get the mapping of prefix to namespace URI for all well-known namespaces
   * provided by default to the static context.
   * <p>
   * These namespaces can be overridden using the
   * {@link Builder#namespace(String, URI)} method.
   *
   * @return the mapping of prefix to namespace URI for all well-known namespaces
   */
  @SuppressFBWarnings("MS_EXPOSE_REP")
  public static Map<String, URI> getWellKnownNamespacesMap() {
    return WELL_KNOWN_NAMESPACES;
  }

  /**
   * Get the mapping of namespace URIs to prefixes for all well-known namespaces
   * provided by default to the static context.
   *
   * @return the mapping of namespace URI to prefix for all well-known namespaces
   */
  @SuppressFBWarnings("MS_EXPOSE_REP")
  public static Map<String, String> getWellKnownURIToPrefixMap() {
    return WELL_KNOWN_URI_TO_PREFIX;
  }

  /**
   * Get the namespace prefix associated with the provided URI, if the URI is
   * well-known.
   *
   * @param uri
   *          the URI to get the prefix for
   * @return the prefix or {@code null} if the provided URI is not well-known
   */
  @Nullable
  public static String getWellKnownPrefixForUri(@NonNull String uri) {
    return WELL_KNOWN_URI_TO_PREFIX.get(uri);
  }

  /**
   * Create a new static context instance using default values.
   *
   * @return a new static context instance
   */
  @NonNull
  public static StaticContext instance() {
    return builder().build();
  }

  private StaticContext(Builder builder) {
    this.baseUri = builder.baseUri;
    this.knownNamespaces = CollectionUtil.unmodifiableMap(ObjectUtils.notNull(Map.copyOf(builder.namespaces)));
    this.defaultModelNamespace = builder.defaultModelNamespace;
    this.defaultFunctionNamespace = builder.defaultFunctionNamespace;
    this.useWildcardWhenNamespaceNotDefaulted = builder.useWildcardWhenNamespaceNotDefaulted;
  }

  /**
   * Get the static base URI to use in resolving URIs handled by the Metapath
   * processor. This URI, if provided, will be used when a document base URI is
   * not available.
   *
   * @return the base URI or {@code null} if not defined
   */
  @Nullable
  public URI getBaseUri() {
    synchronized (this) {
      return baseUri;
    }
  }

  /**
   * Get the namespace URI associated with the provided {@code prefix}, if any is
   * bound.
   * <p>
   * This method uses the namespaces set by the
   * {@link Builder#namespace(String, URI)} method, falling back to the well-known
   * namespace bindings when a prefix match is not found.
   * <p>
   * The well-known namespace bindings can be retrieved using the
   * {@link StaticContext#getWellKnownNamespacesMap()} method.
   *
   * @param prefix
   *          the namespace prefix
   * @return the namespace URI bound to the prefix, or {@code null} if no
   *         namespace is bound to the prefix
   * @see Builder#namespace(String, URI)
   * @see #getWellKnownNamespacesMap()
   */
  @Nullable
  public URI lookupNamespaceURIForPrefix(@NonNull String prefix) {
    URI retval = knownNamespaces.get(prefix);
    if (retval == null) {
      // fall back to well-known namespaces
      retval = WELL_KNOWN_NAMESPACES.get(prefix);
    }
    return retval;
  }

  /**
   * Get the namespace associated with the provided {@code prefix} as a string, if
   * any is bound.
   *
   * @param prefix
   *          the namespace prefix
   * @return the namespace string bound to the prefix, or {@code null} if no
   *         namespace is bound to the prefix
   */
  @Nullable
  public String lookupNamespaceForPrefix(@NonNull String prefix) {
    URI result = lookupNamespaceURIForPrefix(prefix);
    return result == null ? null : result.toASCIIString();
  }

  /**
   * Get the default namespace for assembly, field, or flag references that have
   * no namespace prefix.
   *
   * @return the namespace if defined or {@code null} otherwise
   */
  @Nullable
  public URI getDefaultModelNamespace() {
    return defaultModelNamespace;
  }

  /**
   * Get the default namespace for function references that have no namespace
   * prefix.
   *
   * @return the namespace if defined or {@code null} otherwise
   */
  @Nullable
  public URI getDefaultFunctionNamespace() {
    return defaultFunctionNamespace;
  }

  /**
   * Get a prefix resolver for use with Metapath function names that will attempt
   * to identify the namespace corresponding to a given prefix.
   * <p>
   * This will use the following lookup order, advancing to the next when a
   * {@code null} value is returned:
   * <ol>
   * <li>Lookup the prefix using
   * {@link StaticContext#lookupNamespaceForPrefix(String)}</li>
   * <li>Return the result of
   * {@link StaticContext#getDefaultFunctionNamespace()}</li>
   * <li>Return {@link XMLConstants#NULL_NS_URI}</li>
   * </ol>
   *
   * @return the resolver
   */
  @NonNull
  public PrefixToNamespaceResolver getFunctionPrefixResolver() {
    return this::resolveFunctionPrefix;
  }

  @NonNull
  private String resolveFunctionPrefix(@NonNull String prefix) {
    String ns = lookupNamespaceForPrefix(prefix);
    if (ns == null) {
      URI uri = getDefaultFunctionNamespace();
      if (uri != null) {
        ns = uri.toASCIIString();
      }
    }
    return ns == null ? XMLConstants.NULL_NS_URI : ns;
  }

  /**
   * Get a prefix resolver for use with Metapath flag node names that will attempt
   * to identify the namespace corresponding to a given prefix.
   * <p>
   * This will use the following lookup order, advancing to the next when a
   * {@code null} value is returned:
   * <ol>
   * <li>Lookup the prefix using
   * {@link StaticContext#lookupNamespaceForPrefix(String)}</li>
   * <li>Return {@link XMLConstants#NULL_NS_URI}</li>
   * </ol>
   *
   * @return the resolver
   */
  @NonNull
  public PrefixToNamespaceResolver getFlagPrefixResolver() {
    return this::resolveFlagReferencePrefix;
  }

  @NonNull
  private String resolveFlagReferencePrefix(@NonNull String prefix) {
    String ns = lookupNamespaceForPrefix(prefix);
    return ns == null ? XMLConstants.NULL_NS_URI : ns;
  }

  /**
   * Get a prefix resolver for use with Metapath model node names that will
   * attempt to identify the namespace corresponding to a given prefix.
   * <p>
   * This will use the following lookup order, advancing to the next when a
   * {@code null} value is returned:
   * <ol>
   * <li>Lookup the prefix using
   * {@link StaticContext#lookupNamespaceForPrefix(String)}</li>
   * <li>Return the result of
   * {@link StaticContext#getDefaultModelNamespace()}</li>
   * <li>Return {@link XMLConstants#NULL_NS_URI}</li>
   * </ol>
   *
   * @return the resolver
   */
  @NonNull
  public PrefixToNamespaceResolver getModelPrefixResolver() {
    return this::resolveModelReferencePrefix;
  }

  @NonNull
  private String resolveModelReferencePrefix(@NonNull String prefix) {
    String ns = lookupNamespaceForPrefix(prefix);
    if (ns == null) {
      URI uri = getDefaultModelNamespace();
      if (uri != null) {
        ns = uri.toASCIIString();
      }
    }
    return ns == null ? XMLConstants.NULL_NS_URI : ns;
  }

  /**
   * Get a prefix resolver for use with Metapath variable names that will attempt
   * to identify the namespace corresponding to a given prefix.
   * <p>
   * This will use the following lookup order, advancing to the next when a
   * {@code null} value is returned:
   * <ol>
   * <li>Lookup the prefix using
   * {@link StaticContext#lookupNamespaceForPrefix(String)}</li>
   * <li>Return {@link XMLConstants#NULL_NS_URI}</li>
   * </ol>
   *
   * @return the resolver
   */
  @NonNull
  public PrefixToNamespaceResolver getVariablePrefixResolver() {
    return this::resolveVariablePrefix;
  }

  @NonNull
  private String resolveVariablePrefix(@NonNull String prefix) {
    String ns = lookupNamespaceForPrefix(prefix);
    return ns == null ? XMLConstants.NULL_NS_URI : ns;
  }

  /**
   * Get a new static context builder that is pre-populated with the setting of
   * this static context.
   *
   * @return a new builder
   */
  @NonNull
  public Builder buildFrom() {
    Builder builder = builder();
    builder.baseUri = this.baseUri;
    builder.namespaces.putAll(this.knownNamespaces);
    builder.defaultModelNamespace = this.defaultModelNamespace;
    builder.defaultFunctionNamespace = this.defaultFunctionNamespace;
    return builder;
  }

  /**
   * Indicates if a name match should use a wildcard for the namespace is the
   * namespace does not have a value and the {@link #getDefaultModelNamespace()}
   * is {@code null}.
   *
   * @return {@code true} if a wildcard match on the name space should be used or
   *         {@code false} otherwise
   */
  public boolean isUseWildcardWhenNamespaceNotDefaulted() {
    return useWildcardWhenNamespaceNotDefaulted && getDefaultModelNamespace() == null;
  }

  /**
   * Create a new static context builder that allows for fine-grained adjustments
   * when creating a new static context.
   *
   * @return a new builder
   */
  @NonNull
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder used to generate the static context.
   */
  public static final class Builder {
    public boolean useWildcardWhenNamespaceNotDefaulted; // false
    @Nullable
    private URI baseUri;
    @NonNull
    private final Map<String, URI> namespaces = new ConcurrentHashMap<>();
    @Nullable
    private URI defaultModelNamespace;
    @Nullable
    private URI defaultFunctionNamespace = MetapathConstants.NS_METAPATH_FUNCTIONS;

    private Builder() {
      namespaces.put(
          MetapathConstants.PREFIX_METAPATH,
          MetapathConstants.NS_METAPATH);
      namespaces.put(
          MetapathConstants.PREFIX_XML_SCHEMA,
          MetapathConstants.NS_XML_SCHEMA);
      namespaces.put(
          MetapathConstants.PREFIX_XPATH_FUNCTIONS,
          MetapathConstants.NS_METAPATH_FUNCTIONS);
      namespaces.put(
          MetapathConstants.PREFIX_XPATH_FUNCTIONS_MATH,
          MetapathConstants.NS_METAPATH_FUNCTIONS_MATH);
    }

    /**
     * Sets the static base URI to use in resolving URIs handled by the Metapath
     * processor, when a document base URI is not available. There is only a single
     * base URI. Subsequent calls to this method will change the base URI.
     *
     * @param uri
     *          the base URI to use
     * @return this builder
     */
    @NonNull
    public Builder baseUri(@NonNull URI uri) {
      this.baseUri = uri;
      return this;
    }

    /**
     * Adds a new prefix to namespace URI binding to the mapping of
     * <a href="https://www.w3.org/TR/xpath-31/#dt-static-namespaces">statically
     * known namespaces</a>.
     * <p>
     * A namespace set by this method can be resolved using the
     * {@link StaticContext#lookupNamespaceForPrefix(String)} method.
     * <p>
     * Well-known namespace bindings are used by default, which can be retrieved
     * using the {@link StaticContext#getWellKnownNamespacesMap()} method.
     *
     * @param prefix
     *          the prefix to associate with the namespace, which may be
     * @param uri
     *          the namespace URI
     * @return this builder
     * @see StaticContext#lookupNamespaceForPrefix(String)
     * @see StaticContext#lookupNamespaceURIForPrefix(String)
     * @see StaticContext#getWellKnownNamespacesMap()
     */
    @NonNull
    public Builder namespace(@NonNull String prefix, @NonNull URI uri) {
      this.namespaces.put(prefix, uri);
      return this;
    }

    /**
     * A convenience method for {@link #namespace(String, URI)}.
     *
     * @param prefix
     *          the prefix to associate with the namespace, which may be
     * @param uri
     *          the namespace URI
     * @return this builder
     * @throws IllegalArgumentException
     *           if the provided URI is invalid
     * @see StaticContext#lookupNamespaceForPrefix(String)
     * @see StaticContext#lookupNamespaceURIForPrefix(String)
     * @see StaticContext#getWellKnownNamespacesMap()
     */
    @NonNull
    public Builder namespace(@NonNull String prefix, @NonNull String uri) {
      return namespace(prefix, ObjectUtils.notNull(URI.create(uri)));
    }

    /**
     * Defines the default namespace to use for assembly, field, or flag references
     * that have no namespace prefix.
     *
     * @param uri
     *          the namespace URI
     * @return this builder
     * @see StaticContext#getDefaultModelNamespace()
     */
    @NonNull
    public Builder defaultModelNamespace(@NonNull URI uri) {
      this.defaultModelNamespace = uri;
      return this;
    }

    /**
     * A convenience method for {@link #defaultModelNamespace(URI)}.
     *
     * @param uri
     *          the namespace URI
     * @return this builder
     * @throws IllegalArgumentException
     *           if the provided URI is invalid
     * @see StaticContext#getDefaultModelNamespace()
     */
    @NonNull
    public Builder defaultModelNamespace(@NonNull String uri) {
      return defaultModelNamespace(ObjectUtils.notNull(URI.create(uri)));
    }

    /**
     * Defines the default namespace to use for assembly, field, or flag references
     * that have no namespace prefix.
     *
     * @param uri
     *          the namespace URI
     * @return this builder
     * @see StaticContext#getDefaultFunctionNamespace()
     */
    @NonNull
    public Builder defaultFunctionNamespace(@NonNull URI uri) {
      this.defaultFunctionNamespace = uri;
      return this;
    }

    /**
     * A convenience method for {@link #defaultFunctionNamespace(URI)}.
     *
     * @param uri
     *          the namespace URI
     * @return this builder
     * @throws IllegalArgumentException
     *           if the provided URI is invalid
     * @see StaticContext#getDefaultFunctionNamespace()
     */
    @NonNull
    public Builder defaultFunctionNamespace(@NonNull String uri) {
      return defaultFunctionNamespace(ObjectUtils.notNull(URI.create(uri)));
    }

    /**
     * Set the name matching behavior for when a model node has no namespace.
     *
     * @param value
     *          {@code true} if on or {@code false} otherwise
     * @return this builder
     */
    public Builder useWildcardWhenNamespaceNotDefaulted(boolean value) {
      this.useWildcardWhenNamespaceNotDefaulted = value;
      return this;
    }

    /**
     * Construct a new static context using the information provided to the builder.
     *
     * @return the new static context
     */
    @NonNull
    public StaticContext build() {
      return new StaticContext(this);
    }
  }
}
