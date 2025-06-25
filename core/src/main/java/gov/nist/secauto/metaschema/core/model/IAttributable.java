/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.MetaschemaConstants;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A marker interface for implementations that supports the mapping of a
 * namespace valued key to a set of values.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IAttributable {
  /**
   * The default key namespace for a property.
   */
  @NonNull
  String DEFAULT_PROPERY_NAMESPACE = MetaschemaConstants.METASCHEMA_NAMESPACE;

  /**
   * Get the mapping of property key to values.
   *
   * @return the mapping
   */
  @NonNull
  Map<Key, Set<String>> getProperties();

  /**
   * Determine if a property is defined.
   *
   * @param key
   *          the key of the property
   * @return {@code true} if the property is defined or {@code false} otherwise
   */
  default boolean hasProperty(@NonNull Key key) {
    return getProperties().containsKey(key);
  }

  /**
   * Get the values associated with a given property key.
   *
   * @param key
   *          the key of the property
   * @return the values or an empty set
   */
  @NonNull
  default Set<String> getPropertyValues(@NonNull Key key) {
    Set<String> retval = getProperties().get(key);
    if (retval == null) {
      retval = CollectionUtil.emptySet();
    }
    return retval;
  }

  /**
   * Determine if a given property, with a given {@code key}, has the identified
   * {@code value}.
   *
   * @param key
   *          the key of the property
   * @param value
   *          the expected property value
   * @return {@code true} if the property value is defined or {@code false}
   *         otherwise
   */
  default boolean hasPropertyValue(@NonNull Key key, @NonNull String value) {
    Set<String> values = getProperties().get(key);
    return values != null && values.contains(value);
  }

  /**
   * Get a property key based on the provided name and namespace.
   *
   * @param name
   *          the name portion of a property key
   * @param namespace
   *          the namespace portion of a property key
   * @return the property key
   */
  @NonNull
  static Key key(@NonNull String name, @NonNull String namespace) {
    return new Key(name, namespace);
  }

  /**
   * Get a property key based on the provided name and the default namespace.
   *
   * @param name
   *          the name portion of a property key
   * @return the property key
   * @see #DEFAULT_PROPERY_NAMESPACE
   */
  @NonNull
  static Key key(@NonNull String name) {
    return new Key(name);
  }

  /**
   * Represents a property key based on a name and a namespace.
   */
  // FIXME: use IEnhancedQName instead of name and namespace, or replace key
  // altogether with an integer value
  @SuppressWarnings("PMD.ShortClassName")
  final class Key {
    @NonNull
    private final String name;
    @NonNull
    private final String namespace;

    private Key(@NonNull String name) {
      this(name, DEFAULT_PROPERY_NAMESPACE);
    }

    private Key(@NonNull String name, @NonNull String namespace) {
      this.name = name;
      this.namespace = namespace;
    }

    /**
     * Get the property key's name portion.
     *
     * @return the name
     */
    @NonNull
    public String getName() {
      return name;
    }

    /**
     * Get the property key's namespace portion.
     *
     * @return the name
     */
    @NonNull
    public String getNamespace() {
      return namespace;
    }

    @Override
    public int hashCode() {
      return Objects.hash(name, namespace);
    }

    @SuppressWarnings("PMD.OnlyOneReturn")
    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj instanceof Key)) {
        return false;
      }
      Key other = (Key) obj;
      return Objects.equals(name, other.name) && Objects.equals(namespace, other.namespace);
    }
  }
}
