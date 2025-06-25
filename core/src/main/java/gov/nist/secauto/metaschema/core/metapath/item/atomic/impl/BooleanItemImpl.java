/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.impl.AbstractMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.AbstractAtomicItemBase;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.IOpaqueMapKey;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of a Metapath atomic item with a boolean value.
 */
public class BooleanItemImpl
    extends AbstractAtomicItemBase<Boolean>
    implements IBooleanItem {
  @NonNull
  private static final String TRUE_STRING = "true";
  @NonNull
  private static final String FALSE_STRING = "false";
  @NonNull
  private static final IStringItem TRUE_STRING_ITEM = IStringItem.valueOf(TRUE_STRING);
  @NonNull
  private static final IStringItem FALSE_STRING_ITEM = IStringItem.valueOf(FALSE_STRING);

  private final boolean booleanValue;

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public BooleanItemImpl(boolean value) {
    this.booleanValue = value;
  }

  @Override
  public Boolean getValue() {
    return toBoolean();
  }

  @Override
  public boolean toBoolean() {
    return booleanValue;
  }

  @Override
  public String asString() {
    return toBoolean() ? TRUE_STRING : FALSE_STRING;
  }

  @Override
  public IStringItem asStringItem() {
    return toBoolean() ? TRUE_STRING_ITEM : FALSE_STRING_ITEM;
  }

  @Override
  public IDataTypeAdapter<Boolean> getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.BOOLEAN;
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
    return Boolean.hashCode(booleanValue);
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IBooleanItem && compareTo((IBooleanItem) obj) == 0;
  }

  private final class MapKey
      extends AbstractMapKey
      implements IOpaqueMapKey {
    @Override
    public IBooleanItem getKey() {
      return BooleanItemImpl.this;
    }
  }
}
