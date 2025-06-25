/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.impl.AbstractMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.AbstractAtomicItemBase;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IQNameItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.IOpaqueMapKey;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of a Metapath atomic item with a boolean value.
 */
public class QNameItemImpl
    extends AbstractAtomicItemBase<IEnhancedQName>
    implements IQNameItem {
  @NonNull
  private final IEnhancedQName value;

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public QNameItemImpl(@NonNull IEnhancedQName value) {
    this.value = value;
  }

  @Override
  public IEnhancedQName getValue() {
    return toEnhancedQName();
  }

  @Override
  public IEnhancedQName toEnhancedQName() {
    return value;
  }

  @Override
  public String asString() {
    return toEnhancedQName().toEQName();
  }

  @Override
  public IStringItem asStringItem() {
    return IStringItem.valueOf(asString());
  }

  @Override
  public IDataTypeAdapter<IEnhancedQName> getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.QNAME;
  }

  @Override
  protected String getValueSignature() {
    return asString();
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IQNameItem && compareTo((IQNameItem) obj) == 0;
  }

  private final class MapKey
      extends AbstractMapKey
      implements IOpaqueMapKey {
    @Override
    public IQNameItem getKey() {
      return QNameItemImpl.this;
    }
  }
}
