
package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.type.IItemType;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@SuppressFBWarnings(value = "SING_SINGLETON_GETTER_NOT_SYNCHRONIZED", justification = "false positive")
public final class AnyItemType
    implements IItemType {
  @NonNull
  private static final AnyItemType INSTANCE = new AnyItemType();

  @NonNull
  public static AnyItemType instance() {
    return INSTANCE;
  }

  @Override
  public boolean matches(IItem item) {
    // any item type always matches
    return true;
  }

  @Override
  public Class<? extends IItem> getItemClass() {
    return IItem.class;
  }

  @Override
  public String toSignature() {
    return "item()";
  }

  private AnyItemType() {
    // disable construction
  }
}
