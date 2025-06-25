
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A {@link INodeItem} supported by a {@link IFieldDefinition}, that may have an
 * associated value.
 */
class FieldOrphanedDefinitionNodeItemImpl
    extends AbstractOrphanedDefinitionNodeItem<IFieldDefinition, IFieldInstance>
    implements IFieldNodeItem,
    IFeatureOrhpanedDefinitionModelNodeItem<IFieldDefinition, IFieldInstance>,
    IFeatureNoDataAtomicValuedItem,
    IFeatureFlagContainerItem {
  private final Lazy<FlagContainer> model;

  public FieldOrphanedDefinitionNodeItemImpl(
      @NonNull IFieldDefinition definition,
      @Nullable URI baseUri,
      @NonNull INodeItemGenerator generator) {
    super(definition, baseUri);
    this.model = Lazy.of(generator.newMetaschemaModelSupplier(this));
  }

  @SuppressWarnings("null")
  @Override
  public FlagContainer getModel() {
    return model.get();
  }

  @Override
  public String stringValue() {
    return "";
  }
}
