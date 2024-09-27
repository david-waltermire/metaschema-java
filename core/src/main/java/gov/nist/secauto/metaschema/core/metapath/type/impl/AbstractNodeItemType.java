
package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

public abstract class AbstractNodeItemType<I extends INodeItem>
    extends AbstractItemType<I> {
  @NonNull
  private final String nodeName;

  protected AbstractNodeItemType(
      @NonNull String name,
      @NonNull Class<? extends I> itemClass) {
    super(itemClass);
    this.nodeName = name;
  }

  @NonNull
  public String getNodeName() {
    return nodeName;
  }

  @NonNull
  protected abstract String getTest();

  @Override
  public String toSignature() {
    return ObjectUtils.notNull(new StringBuilder()
        .append(getNodeName())
        .append('(')
        .append(getTest())
        .append(')')
        .toString());
  }

}
