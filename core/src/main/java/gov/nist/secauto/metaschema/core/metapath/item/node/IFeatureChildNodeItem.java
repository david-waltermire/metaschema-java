
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a node item for a Metaschema model instance the is always a child
 * of another item in the Metaschema model.
 */
public interface IFeatureChildNodeItem extends INodeItem {
  @Override
  @NonNull
  INodeItem getParentNodeItem();

  @Override
  default StaticContext getStaticContext() {
    return getParentNodeItem().getStaticContext();
  }
}
