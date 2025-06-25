
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class AssemblyOrphanedDefinitionNodeItemImpl
    extends AbstractOrphanedDefinitionNodeItem<IAssemblyDefinition, IAssemblyInstance>
    implements IAssemblyNodeItem,
    IFeatureOrhpanedDefinitionModelNodeItem<IAssemblyDefinition, IAssemblyInstance>,
    IFeatureModelContainerItem, IFeatureNoDataValuedItem {
  @NonNull
  private final Lazy<ModelContainer> model;

  public AssemblyOrphanedDefinitionNodeItemImpl(
      @NonNull IAssemblyDefinition definition,
      @Nullable URI baseUri,
      @NonNull INodeItemGenerator generator) {
    super(definition, baseUri);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newMetaschemaModelSupplier(this)));
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

  @Override
  public String stringValue() {
    return "";
  }

}
