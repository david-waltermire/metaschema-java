/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.adapter.UuidAdapter;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.AbstractAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IUuidItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.impl.AbstractStringMapKey;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.UUID;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * An implementation of a Metapath atomic item containing a UUID data value.
 */
public class UuidItemImpl
    extends AbstractAnyAtomicItem<UUID>
    implements IUuidItem {
  @SuppressWarnings("synthetic-access")
  private final Lazy<String> stringValue = Lazy.of(super::asString);

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public UuidItemImpl(@NonNull UUID value) {
    super(value);
  }

  @Override
  public UUID asUuid() {
    return getValue();
  }

  @Override
  public String asString() {
    return ObjectUtils.notNull(stringValue.get());
  }

  @Override
  public UuidAdapter getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.UUID;
  }

  @Override
  public int hashCode() {
    return asString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IStringItem && compareTo((IStringItem) obj) == 0;
  }

  @Override
  public IStringItem normalizeSpace() {
    // noop
    return this;
  }

  @Override
  protected String getValueSignature() {
    return "'" + asString() + "'";
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  private final class MapKey
      extends AbstractStringMapKey {
    @Override
    public IUuidItem getKey() {
      return UuidItemImpl.this;
    }

    @Override
    public String asString() {
      return getKey().asString();
    }
  }
}
