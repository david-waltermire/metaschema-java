
package gov.nist.secauto.metaschema.core.metapath.item.node;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.Nullable;

public interface IDocumentBasedNodeItem extends INodeItem {

  @Override
  default IModelNodeItem<?, ?> getParentContentNodeItem() {
    // there is no parent
    return null;
  }

  /**
   * Get the URI associated with this document.
   *
   * @return the document's URI or {@code null} if unavailable
   */
  @Nullable
  URI getDocumentUri();

  @Override
  default URI getBaseUri() {
    return getDocumentUri();
  }

  @Override
  default INodeItem getParentNodeItem() {
    // there is no parent
    return null;
  }

}
