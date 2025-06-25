
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A {@link INodeItem} supported by a {@link IFieldInstance}, that may have an
 * associated value.
 */
class FieldInstanceNodeItemImpl
    extends AbstractInstanceNodeItem<IFieldDefinition, IFieldInstance, IAssemblyNodeItem>
    implements IFieldNodeItem,
    IFeatureAtomicValuedItem,
    IFeatureFlagContainerItem,
    IFeatureChildNodeItem {

  private final int position;

  @NonNull
  private final Lazy<FlagContainer> model;
  @NonNull
  private final Object value;

  /**
   * Used to cache this object as an atomic item.
   */
  @NonNull
  private final Lazy<IAnyAtomicItem> atomicItem;

  public FieldInstanceNodeItemImpl(
      @NonNull IFieldInstance instance,
      @NonNull IAssemblyNodeItem parent,
      int position,
      @NonNull Object value,
      @NonNull INodeItemGenerator generator) {
    super(instance, parent);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newDataModelSupplier(this)));
    this.position = position;
    this.value = value;
    this.atomicItem = ObjectUtils.notNull(Lazy.of(this::newAtomicItem));
  }

  @SuppressWarnings("null")
  @Override
  public FlagContainer getModel() {
    return model.get();
  }

  @Override
  public int getPosition() {
    return position;
  }

  @Override
  public Object getValue() {
    return value;
  }

  @Override
  public Object getAtomicValue() {
    Object value = getValue();
    return getDefinition().getFieldValue(value);
  }

  @Override
  public IAnyAtomicItem toAtomicItem() {
    return atomicItem.get();
  }

  @Override
  public String stringValue() {
    return toAtomicItem().asString();
  }

  @Override
  protected String getValueSignature() {
    return toAtomicItem().toSignature();
  }
}
