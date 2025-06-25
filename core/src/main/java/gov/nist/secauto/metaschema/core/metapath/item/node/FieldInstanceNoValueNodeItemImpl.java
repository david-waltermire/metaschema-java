
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class FieldInstanceNoValueNodeItemImpl
    extends AbstractInstanceNodeItem<IFieldDefinition, IFieldInstance, IAssemblyNodeItem>
    implements IFieldNodeItem,
    IFeatureNoDataAtomicValuedItem,
    IFeatureFlagContainerItem,
    IFeatureChildNodeItem {

  @NonNull
  private final Lazy<FlagContainer> model;

  public FieldInstanceNoValueNodeItemImpl(
      @NonNull IFieldInstance instance,
      @NonNull IAssemblyNodeItem parent,
      @NonNull INodeItemGenerator generator) {
    super(instance, parent);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newMetaschemaModelSupplier(this)));
  }

  @SuppressWarnings("null")
  @Override
  public FlagContainer getModel() {
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
