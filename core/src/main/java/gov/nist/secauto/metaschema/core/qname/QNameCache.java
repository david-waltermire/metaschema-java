/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.qname;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Provides a cache for managing commonly reused qualified names, represented
 * using the {@link IEnhancedQName} interface.
 * <p>
 * The cache operations provided by this cache are thread safe.
 * <p>
 * A unique integer index value is assigned for each namespace and localname
 * pair. This index value can be used to retrieve the qualified name using the
 * {@link #get(int)} method. This allows the index value to be used in place of
 * the actual qualified name.
 * <p>
 * The {@link IEnhancedQName#getIndexPosition()} method can be used to get the
 * index value of a given qualified name.
 */
// FIXME: Consider the implications of this cache in a long running process.
// Using a global shared instance may result in a very large cache.
public final class QNameCache {

  private static final Comparator<IEnhancedQName> COMPARATOR
      = Comparator.comparingInt(IEnhancedQName::getIndexPosition);

  @NonNull
  private static final Lazy<QNameCache> INSTANCE = ObjectUtils.notNull(Lazy.of(QNameCache::new));

  @NonNull
  private final NamespaceCache namespaceCache;

  private final Map<Integer, QNameRecord> indexToQName = new ConcurrentHashMap<>();
  private final Map<Integer, Map<String, QNameRecord>> nsIndexToLocalNameToIndex = new ConcurrentHashMap<>();

  /**
   * The next available qualified-name index position.
   */
  private final AtomicInteger indexCounter = new AtomicInteger();

  /**
   * Get the singleton qualified name cache.
   *
   * @return the singleton instance
   */
  @NonNull
  public static QNameCache instance() {
    return ObjectUtils.notNull(INSTANCE.get());
  }

  private QNameCache() {
    // disable construction
    this(NamespaceCache.instance());
  }

  private QNameCache(@NonNull NamespaceCache nsCache) {
    this.namespaceCache = nsCache;
  }

  @NonNull
  private NamespaceCache getNamespaceCache() {
    return namespaceCache;
  }

  /**
   * Get a cached qualified name based on the provided namespace and name.
   * <p>
   * The qualified name will be added to the cache if it doesn't already exist.
   *
   * @param namespace
   *          the namespace for the new qualified name
   * @param name
   *          the local name for the new qualified name
   * @return the new cached qualified name or the existing cached name if it
   *         already exists in the cache
   */
  @NonNull
  public IEnhancedQName cachedQNameFor(@NonNull String namespace, @NonNull String name) {
    int namespacePosition = namespaceCache.indexOf(namespace);

    Map<String, QNameRecord> namespaceNames = nsIndexToLocalNameToIndex
        .computeIfAbsent(namespacePosition, key -> new ConcurrentHashMap<>());

    return ObjectUtils.notNull(namespaceNames.computeIfAbsent(name, key -> {
      assert key != null;
      QNameRecord record = new QNameRecord(namespacePosition, namespace, key);
      indexToQName.put(record.getIndexPosition(), record);
      return record;
    }));
  }

  /**
   * Get an existing qualified name from the cache based on the provided namespace
   * and name.
   *
   * @param namespace
   *          the namespace for the qualified name
   * @param name
   *          the local name for the qualified name
   * @return an optional containing the cached qualified name or a {@code null}
   *         value if the name does not exist in the cache
   */
  @NonNull
  Optional<IEnhancedQName> get(@NonNull String namespace, @NonNull String name) {
    Optional<Integer> nsPosition = namespaceCache.get(namespace);
    if (!nsPosition.isPresent()) {
      throw new IllegalArgumentException(
          String.format("The namespace '%s' is not recognized.", namespace));
    }

    Map<String, QNameRecord> namespaceNames = nsIndexToLocalNameToIndex.get(nsPosition.get());
    return ObjectUtils.notNull(Optional.ofNullable(
        namespaceNames == null
            ? null
            : namespaceNames.get(name)));
  }

  /**
   * Get an existing qualified name from the cache that is assigned to the
   * provided index value.
   * <p>
   * Note: There is a chance that an entry associated index value may not exist at
   * first, but subsequent calls may find an associated value in the future if one
   * is created with that value.
   *
   * @param index
   *          the index value for the qualified name
   * @return the cached qualified name or {@code null} if a cache entry does not
   *         exist for the index value
   */
  @Nullable
  public IEnhancedQName get(int index) {
    return indexToQName.get(index);
  }

  private final class QNameRecord implements IEnhancedQName {
    private final int qnameIndexPosition;
    private final int namespaceIndexPosition;
    @NonNull
    private final String namespace;
    @NonNull
    private final String localName;

    public QNameRecord(
        int namespaceIndexPosition,
        @NonNull String namespace,
        @NonNull String localName) {
      this.qnameIndexPosition = indexCounter.getAndIncrement();
      this.namespaceIndexPosition = namespaceIndexPosition;
      this.namespace = namespace;
      this.localName = localName;
    }

    @Override
    public int getIndexPosition() {
      return qnameIndexPosition;
    }

    @Override
    public URI getNamespaceAsUri() {
      return ObjectUtils.notNull(getNamespaceCache().getAsURI(namespaceIndexPosition).get());
    }

    @Override
    public String getNamespace() {
      return namespace;
    }

    @Override
    public String getLocalName() {
      return localName;
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(qnameIndexPosition);
    }

    @SuppressWarnings("PMD.OnlyOneReturn")
    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || getClass() != obj.getClass()) {
        return false;
      }
      QNameRecord other = (QNameRecord) obj;
      return Objects.equals(qnameIndexPosition, other.getIndexPosition());
    }

    @Override
    public int compareTo(IEnhancedQName other) {
      return COMPARATOR.compare(this, other);
    }

    @Override
    public String toString() {
      return toEQName();
    }
  }

}
