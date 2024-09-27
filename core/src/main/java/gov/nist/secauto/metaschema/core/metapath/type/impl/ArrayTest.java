
package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.type.IArrayTest;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ArrayTest implements IArrayTest {
  @NonNull
  private final ISequenceType valueType;

  public ArrayTest(@NonNull ISequenceType valueType) {
    this.valueType = valueType;
  }

  public ISequenceType getValueType() {
    return valueType;
  }

  @Override
  public boolean matches(IItem item) {
    return item instanceof IArrayItem
        ? ((IArrayItem<?>) item).stream().allMatch(valueType::matches)
        : false;
  }

  @Override
  public Class<? extends IItem> getItemClass() {
    return IArrayItem.class;
  }

  @Override
  public String toSignature() {
    return ObjectUtils.notNull(
        new StringBuilder()
            .append("array(")
            .append(getValueType().toSignature())
            .append(')')
            .toString());
  }
}
