
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class AssemblyInstanceNoValueNodeItemImpl
    extends AbstractInstanceNodeItem<IAssemblyDefinition, IAssemblyInstance, IAssemblyNodeItem>
    implements IAssemblyNodeItem,
    IFeatureNoDataValuedItem,
    IFeatureModelContainerItem,
    IFeatureChildNodeItem {

  @NonNull
  private final Lazy<ModelContainer> model;

  public AssemblyInstanceNoValueNodeItemImpl(
      @NonNull IAssemblyInstance instance,
      @NonNull IAssemblyNodeItem parent,
      @NonNull INodeItemGenerator generator) {
    super(instance, parent);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newMetaschemaModelSupplier(this)));
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

  @Override
  public int getPosition() {
    return 1;
  }

  @Override
  public String stringValue() {
    return "";
  }

  @Override
  protected String getValueSignature() {
    return null;
  }
}
