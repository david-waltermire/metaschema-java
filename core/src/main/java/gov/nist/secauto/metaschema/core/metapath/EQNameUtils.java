/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public final class EQNameUtils {
  private static final Pattern URI_QUALIFIED_NAME = Pattern.compile("^Q\\{([^{}]*)\\}(.+)$");
  private static final Pattern LEXICAL_NAME = Pattern.compile("^(?:([^:]+):)?(.+)$");
  private static final Pattern NCNAME = Pattern.compile(String.format("^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$"));

  private EQNameUtils() {
    // disable construction
  }

  /**
   * Parse a name as a qualified name.
   * <p>
   * The name can be:
   * <ul>
   * <li>A URI qualified name of the form <code>Q{URI}name</code>, where the URI
   * represents the namespace</li>
   * <li>A lexical name of the forms <code>prefix:name</code> or
   * <code>name</code>, where the prefix represents the namespace</li>
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
  public static QName parseName(
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
  public static QName parseUriQualifiedName(@NonNull String name) {
    Matcher matcher = URI_QUALIFIED_NAME.matcher(name);
    if (!matcher.matches()) {
      throw new IllegalArgumentException(
          String.format("The name '%s' is not a valid BracedURILiteral of the form: Q{URI}local-name", name));
    }
    return newUriQualifiedName(matcher);
  }

  @NonNull
  private static QName newUriQualifiedName(@NonNull Matcher matcher) {
    return new QName(matcher.group(1), matcher.group(2));
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
  public static QName parseLexicalQName(
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
    return new QName(namespace, matcher.group(2), prefix);
  }

  /**
   * Determine if the name is a non-colonized name.
   *
   * @param name
   *          the name to test
   * @return {@code true} if the name is not colonized, or {@code false} otherwise
   */
  public static boolean isNcName(@NonNull String name) {
    return NCNAME.matcher(name).matches();
  }

  @NonNull
  public static String toEQName(
      @NonNull QName qname,
      @Nullable NamespaceToPrefixResolver resolver) {
    String namespace = qname.getNamespaceURI();
    String prefix = namespace.isEmpty() ? null : StaticContext.getWellKnownPrefixForUri(namespace);
    if (prefix == null && resolver != null) {
      prefix = resolver.resolve(namespace);
    }

    return prefix == null ? ObjectUtils.notNull(qname.toString()) : prefix + ":" + qname.getLocalPart();
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
     * @return the URI string
     */
    @NonNull
    String resolve(@NonNull String prefix);
  }

  /**
   * Provides a callback for resolving namespace prefixes.
   */
  @FunctionalInterface
  public interface NamespaceToPrefixResolver {
    /**
     * Get the URI string for the provided namespace prefix.
     *
     * @param namespace
     *          the namespace URI
     * @return the associated prefix or {@code null} if no prefix is associated
     */
    @Nullable
    String resolve(@NonNull String namespace);
  }
}
