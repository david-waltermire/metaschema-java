
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A {@link INodeItem} supported by a {@link IAssemblyInstance}, that may have
 * an associated value.
 */
class AssemblyInstanceNodeItemImpl
    extends AbstractInstanceNodeItem<IAssemblyDefinition, IAssemblyInstance, IAssemblyNodeItem>
    implements IAssemblyNodeItem,
    IFeatureModelContainerItem,
    IFeatureChildNodeItem {

  private final int position;
  @NonNull
  private final Lazy<ModelContainer> model;
  @NonNull
  private final Object value;

  public AssemblyInstanceNodeItemImpl(
      @NonNull IAssemblyInstance instance,
      @NonNull IAssemblyNodeItem parent,
      int position,
      @NonNull Object value,
      @NonNull INodeItemGenerator generator) {
    super(instance, parent);
    this.model = ObjectUtils.notNull(Lazy.of(generator.newDataModelSupplier(this)));
    this.position = position;
    this.value = value;
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
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
  public String stringValue() {
    return ObjectUtils.notNull(modelItems()
        .map(INodeItem::stringValue)
        .collect(Collectors.joining()));
  }

  @Override
  protected String getValueSignature() {
    return null;
  }
}
