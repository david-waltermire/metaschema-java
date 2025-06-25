
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class AssemblyOrphanedDefinitionDataNodeItemImpl
    extends AbstractOrphanedDefinitionNodeItem<IAssemblyDefinition, IAssemblyInstance>
    implements IAssemblyNodeItem,
    IFeatureModelContainerItem,
    IFeatureRequiredDataItem,
    IFeatureOrhpanedDefinitionModelNodeItem<IAssemblyDefinition, IAssemblyInstance> {
  @NonNull
  private final Lazy<ModelContainer> model;
  @NonNull
  private final Object value;

  public AssemblyOrphanedDefinitionDataNodeItemImpl(
      @NonNull IAssemblyDefinition definition,
      @Nullable URI baseUri,
      @NonNull Object value,
      @NonNull INodeItemGenerator generator) {
    super(definition, baseUri);
    this.value = value;
    this.model = ObjectUtils.notNull(Lazy.of(generator.newDataModelSupplier(this)));
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

  @Override
  public Object getValue() {
    return value;
  }

  @Override
  public String stringValue() {
    return ObjectUtils.notNull(modelItems()
        .map(INodeItem::stringValue)
        .collect(Collectors.joining()));
  }
}
