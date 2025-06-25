
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class AssemblyGlobalDefinitionNodeItemImpl
    extends AbstractGlobalDefinitionNodeItem<IAssemblyDefinition, IAssemblyInstance>
    implements IAssemblyNodeItem,
    IFeatureOrhpanedDefinitionModelNodeItem<IAssemblyDefinition, IAssemblyInstance>,
    IFeatureModelContainerItem, IFeatureNoDataValuedItem {

  @NonNull
  private final Lazy<ModelContainer> model;

  protected AssemblyGlobalDefinitionNodeItemImpl(
      @NonNull IAssemblyDefinition definition,
      @NonNull IModuleNodeItem metaschemaNodeItem,
      @NonNull INodeItemGenerator generator) {
    super(definition, metaschemaNodeItem);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newMetaschemaModelSupplier(this)));
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

}
