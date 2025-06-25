/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.qname;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * An integer-based cache of namespaces to reduce the memory footprint of
 * namespaces used by reusing instances with the same namespace.
 */
public final class NamespaceCache {
  @NonNull
  private static final Lazy<NamespaceCache> INSTANCE = ObjectUtils.notNull(Lazy.of(NamespaceCache::new));

  private final Map<String, Integer> nsToIndex = new ConcurrentHashMap<>();
  private final Map<Integer, String> indexToNs = new ConcurrentHashMap<>();
  private final Map<Integer, URI> indexToNsUri = new ConcurrentHashMap<>();
  /**
   * The next available namespace index position.
   * <p>
   * This value starts at 1, since the "" no namspace has the zero position.
   */
  private final AtomicInteger indexCounter = new AtomicInteger();

  /**
   * Get the singleton instance.
   *
   * @return the singleton instance
   */
  @NonNull
  public static NamespaceCache instance() {
    return ObjectUtils.notNull(INSTANCE.get());
  }

  private NamespaceCache() {
    // claim the "0" position
    int noNamespaceIndex = indexOf("");
    assert noNamespaceIndex == 0;
  }

  /**
   * Get the index value of the provided namespace.
   *
   * @param namespace
   *          the namespace
   * @return the index value
   */
  public int indexOf(@NonNull String namespace) {
    return nsToIndex.computeIfAbsent(namespace, key -> {
      int nextIndex = indexCounter.getAndIncrement();
      indexToNs.put(nextIndex, namespace);
      return nextIndex;
    });
  }

  /**
   * Lookup the index value for an existing namespace.
   *
   * @param namespace
   *          the namespace to lookup
   * @return an optional containing the index value, if it exists
   */
  @NonNull
  public Optional<Integer> get(@NonNull String namespace) {
    return ObjectUtils.notNull(Optional.ofNullable(nsToIndex.get(namespace)));
  }

  /**
   * Lookup the namespace using the index value for an existing namespace.
   *
   * @param index
   *          the index value to lookup
   * @return an optional containing the namespace, if the index value exists
   */
  @NonNull
  public Optional<String> get(int index) {
    return ObjectUtils.notNull(Optional.ofNullable(indexToNs.get(index)));
  }

  /**
   * Lookup the namespace using the index value for an existing namespace.
   *
   * @param index
   *          the index value to lookup
   * @return an optional containing the namespace as a URI, if the index value
   *         exists
   */
  @NonNull
  public Optional<URI> getAsURI(int index) {
    return ObjectUtils.notNull(Optional.ofNullable(indexToNsUri.computeIfAbsent(index, key -> {
      Optional<String> namespace = get(key);
      URI nsUri = null;
      if (namespace.isPresent()) {
        nsUri = URI.create(namespace.get());
        indexToNsUri.put(key, nsUri);
      }
      return nsUri;
    })));
  }
}
