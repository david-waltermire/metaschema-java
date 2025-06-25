
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.IResourceLocation;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class ModuleNodeItemImpl
    extends AbstractNodeItem
    implements IModuleNodeItem, IFeatureModelContainerItem {
  @NonNull
  private final IModule module;

  @NonNull
  private final Lazy<ModelContainer> model;

  public ModuleNodeItemImpl(
      @NonNull IModule module,
      @NonNull INodeItemGenerator generator) {
    this.module = module;
    this.model = ObjectUtils.notNull(Lazy.of(generator.newMetaschemaModelSupplier(this)));
  }

  @NonNull
  public URI getNamespace() {
    return getModule().getXmlNamespace();
  }

  @Override
  public IModule getModule() {
    return module;
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

  @Override
  public IResourceLocation getLocation() {
    // no location
    return null;
  }

  @Override
  public String stringValue() {
    return "";
  }

  @Override
  protected String getValueSignature() {
    return getModule().getLocationHint();
  }
}
