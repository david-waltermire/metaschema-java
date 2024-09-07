/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.adapter.UuidAdapter;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;

import java.util.UUID;

import edu.umd.cs.findbugs.annotations.NonNull;

class UuidItemImpl
    extends AbstractAnyAtomicItem<UUID>
    implements IUuidItem {

  public UuidItemImpl(@NonNull UUID value) {
    super(value);
  }

  @Override
  public UUID asUuid() {
    return getValue();
  }

  @Override
  public UuidAdapter getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.UUID;
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  @Override
  public String asString() {
    return asUuid().toString();
  }

  @Override
  public int hashCode() {
    return asString().hashCode();
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  @Override
  public boolean equals(Object obj) {
    return this == obj
        || (obj instanceof IStringItem && compareTo((IStringItem) obj) == 0);
  }

  private final class MapKey implements IMapKey {
    @Override
    public IUuidItem getKey() {
      return UuidItemImpl.this;
    }

    @Override
    public int hashCode() {
      return getKey().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      return this == obj ||
          (obj instanceof MapKey
              && getKey().asUuid().equals(((MapKey) obj).getKey().asUuid()));
    }
  }
}
