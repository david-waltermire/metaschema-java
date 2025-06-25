
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class FieldGlobalDefinitionNodeItemImpl
    extends AbstractGlobalDefinitionNodeItem<IFieldDefinition, IFieldInstance>
    implements IFieldNodeItem,
    IFeatureOrhpanedDefinitionModelNodeItem<IFieldDefinition, IFieldInstance>,
    IFeatureNoDataAtomicValuedItem,
    IFeatureFlagContainerItem {

  private final Lazy<FlagContainer> model;

  protected FieldGlobalDefinitionNodeItemImpl(
      @NonNull IFieldDefinition definition,
      @NonNull IModuleNodeItem metaschemaNodeItem,
      @NonNull INodeItemGenerator generator) {
    super(definition, metaschemaNodeItem);
    this.model = Lazy.of(generator.newMetaschemaModelSupplier(this));
  }

  @SuppressWarnings("null")
  @Override
  public FlagContainer getModel() {
    return model.get();
  }
}
