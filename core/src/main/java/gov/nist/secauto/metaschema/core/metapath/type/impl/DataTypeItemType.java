
package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.EQNameUtils;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;

import edu.umd.cs.findbugs.annotations.NonNull;

public class DataTypeItemType
    implements IItemType {

  @NonNull
  private final IDataTypeAdapter<?> adapter;

  public DataTypeItemType(@NonNull IDataTypeAdapter<?> adapter) {
    this.adapter = adapter;
  }

  @NonNull
  public IDataTypeAdapter<?> getAdapter() {
    return adapter;
  }

  @Override
  public Class<? extends IAnyAtomicItem> getItemClass() {
    return getAdapter().getItemClass();
  }

  @Override
  public boolean matches(IItem item) {
    return getItemClass().isInstance(item);
  }

  @Override
  public String toSignature() {
    return EQNameUtils.toEQName(getAdapter().getPreferredName(), null);
  }
}
