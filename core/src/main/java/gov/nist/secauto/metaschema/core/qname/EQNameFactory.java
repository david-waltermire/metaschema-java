/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.qname;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A factory that produces qualified names.
 * <p>
 * This implementation uses an underlying integer-based cache to reduce the
 * memory footprint of qualified names and namespaces by reusing instances with
 * the same namespace and local name.
 */
public final class EQNameFactory {
  private static final Pattern URI_QUALIFIED_NAME = Pattern.compile("^Q\\{([^{}]*)\\}(.+)$");
  private static final Pattern LEXICAL_NAME = Pattern.compile("^(?:([^:]+):)?(.+)$");
  @NonNull
  private static final Lazy<EQNameFactory> INSTANCE = ObjectUtils.notNull(Lazy.of(EQNameFactory::new));

  @NonNull
  private final QNameCache cache;

  /**
   * Get the singleton instance.
   *
   * @return the singleton instance
   */
  @NonNull
  public static EQNameFactory instance() {
    return ObjectUtils.notNull(INSTANCE.get());
  }

  private EQNameFactory() {
    // disable construction
    this(QNameCache.instance());
  }

  private EQNameFactory(@NonNull QNameCache cache) {
    this.cache = cache;
  }

  /**
   * Get an existing qualified name by looking up the cached entry using the
   * provided index value.
   *
   * @param index
   *          the index value to lookup
   * @return an optional containing the qualified name, if it exists
   */
  @NonNull
  public Optional<IEnhancedQName> get(int index) {
    return ObjectUtils.notNull(Optional.ofNullable(cache.get(index)));
  }

  /**
   * Get a new qualified name based on the provided namespace and local name.
   *
   * @param namespace
   *          the namespace part of the qualified name
   * @param localName
   *          the local part of the qualified name
   *
   * @return the qualified name
   */
  @NonNull
  public IEnhancedQName newQName(@NonNull String namespace, @NonNull String localName) {
    return cache.cachedQNameFor(namespace, localName);
  }

  /**
   * Parse a name as a qualified name.
   * <p>
   * The name can be:
   * <ul>
   * <li>A URI qualified name of the form <code>Q{URI}name</code>, where the URI
   * represents the namespace
   * <li>A lexical name of the forms <code>prefix:name</code> or
   * <code>name</code>, where the prefix represents the namespace
   * </ul>
   *
   * @param name
   *          the name to parse
   * @param resolver
   *          the prefix resolver to use to determine the namespace for a given
   *          prefix
   * @return the parsed qualified name
   */
  @NonNull
  public IEnhancedQName parseName(
      @NonNull String name,
      @NonNull PrefixToNamespaceResolver resolver) {
    Matcher matcher = URI_QUALIFIED_NAME.matcher(name);
    return matcher.matches()
        ? newUriQualifiedName(matcher)
        : parseLexicalQName(name, resolver);
  }

  /**
   * Parse a URI qualified name.
   * <p>
   * The name is expected to be a URI qualified name of the form
   * <code>{URI}name</code>, where the URI represents the namespace.
   *
   * @param name
   *          the name to parse
   * @return the parsed qualified name
   */
  @NonNull
  public IEnhancedQName parseUriQualifiedName(@NonNull String name) {
    Matcher matcher = URI_QUALIFIED_NAME.matcher(name);
    if (!matcher.matches()) {
      throw new IllegalArgumentException(
          String.format("The name '%s' is not a valid BracedURILiteral of the form: Q{URI}local-name", name));
    }
    return newUriQualifiedName(matcher);
  }

  @NonNull
  private IEnhancedQName newUriQualifiedName(@NonNull Matcher matcher) {
    return cache.cachedQNameFor(
        ObjectUtils.notNull(matcher.group(1)),
        ObjectUtils.notNull(matcher.group(2)));
  }

  /**
   * Parse a lexical name as a qualified name.
   * <p>
   * The name is expected to be a lexical name of the forms
   * <code>prefix:name</code> or <code>name</code>, where the prefix represents
   * the namespace.
   *
   * @param name
   *          the name to parse
   * @param resolver
   *          the prefix resolver to use to determine the namespace for a given
   *          prefix
   * @return the parsed qualified name
   */
  @NonNull
  public IEnhancedQName parseLexicalQName(
      @NonNull String name,
      @NonNull PrefixToNamespaceResolver resolver) {
    Matcher matcher = LEXICAL_NAME.matcher(name);
    if (!matcher.matches()) {
      throw new IllegalArgumentException(
          String.format("The name '%s' is not a valid lexical QName of the form: prefix:local-name or local-name",
              name));
    }
    String prefix = matcher.group(1);

    if (prefix == null) {
      prefix = XMLConstants.DEFAULT_NS_PREFIX;
    }

    String namespace = resolver.resolve(prefix);
    if (namespace == null) {
      throw new IllegalArgumentException(
          String.format("The prefix '%s' is not bound for name '%s'",
              prefix,
              name));
    }
    return cache.cachedQNameFor(namespace, ObjectUtils.notNull(matcher.group(2)));
  }

  /**
   * Provides a callback for resolving namespace prefixes.
   */
  @FunctionalInterface
  public interface PrefixToNamespaceResolver {
    /**
     * Get the URI string for the provided namespace prefix.
     *
     * @param prefix
     *          the namespace prefix
     * @return the URI string or {@code null} if the prefix is unbound
     */
    @Nullable
    String resolve(@NonNull String prefix);
  }

}
