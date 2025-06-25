/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.AbstractAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyUriItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.impl.AbstractStringMapKey;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * An abstract implementation of a Metapath atomic item containing a URI data
 * value.
 */
public abstract class AbstractUriItem
    extends AbstractAnyAtomicItem<URI>
    implements IAnyUriItem {

  @SuppressWarnings("synthetic-access")
  private final Lazy<String> stringValue = Lazy.of(super::asString);

  /**
   * Construct a new item that wraps the provided value.
   *
   * @param value
   *          the value to wrap
   */
  protected AbstractUriItem(@NonNull URI value) {
    super(value);
  }

  @Override
  @NonNull
  public URI asUri() {
    return getValue();
  }

  @Override
  public String asString() {
    return ObjectUtils.notNull(stringValue.get());
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  @Override
  public int hashCode() {
    return asUri().hashCode();
  }

  @Override
  protected String getValueSignature() {
    return "'" + asString() + "'";
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IAnyUriItem && compareTo((IAnyUriItem) obj) == 0;

  }

  private final class MapKey
      extends AbstractStringMapKey {

    @Override
    public IAnyUriItem getKey() {
      return AbstractUriItem.this;
    }

    @Override
    public String asString() {
      return getKey().asString();
    }
  }
}
