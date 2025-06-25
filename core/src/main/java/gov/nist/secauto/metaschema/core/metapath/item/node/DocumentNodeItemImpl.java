
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IResourceLocation;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class DocumentNodeItemImpl
    extends AbstractNodeItem
    implements IDocumentNodeItem, IFeatureModelContainerItem {
  @NonNull
  private final IRootAssemblyNodeItem root;
  @NonNull
  private final URI documentUri;
  @NonNull
  private final Lazy<ModelContainer> model;
  @NonNull
  private final StaticContext staticContext;

  public DocumentNodeItemImpl(
      @NonNull IAssemblyDefinition root,
      @NonNull Object rootValue,
      @NonNull URI documentUri,
      @NonNull INodeItemGenerator generator) {
    this.root = new RootAssemblyValuedNodeItemImpl(root, this, rootValue, generator);
    this.documentUri = documentUri;
    this.model = ObjectUtils.notNull(Lazy.of(generator.newDataModelSupplier(this.root)));

    StaticContext.Builder builder = StaticContext.builder()
        .baseUri(documentUri)
        .defaultModelNamespace(ObjectUtils.requireNonNull(root.getRootQName().getNamespace()));

    // obj.getNamespaceBindingList().stream()
    // .forEach(binding -> builder.namespace(
    // ObjectUtils.notNull(binding.getPrefix()),
    // ObjectUtils.notNull(binding.getUri())));

    this.staticContext = builder.build();
  }

  @Override
  @NonNull
  public IRootAssemblyNodeItem getRootAssemblyNodeItem() {
    return root;
  }

  @Override
  @NonNull
  public URI getDocumentUri() {
    return documentUri;
  }

  @SuppressWarnings("null")
  @Override
  public ModelContainer getModel() {
    return model.get();
  }

  @Override
  public Object getValue() {
    return getRootAssemblyNodeItem().getValue();
  }

  @Override
  public IResourceLocation getLocation() {
    return getRootAssemblyNodeItem().getLocation();
  }

  @Override
  public StaticContext getStaticContext() {
    return staticContext;
  }

  @Override
  public String stringValue() {
    return getRootAssemblyNodeItem().stringValue();
  }

  @Override
  protected String getValueSignature() {
    return null;
  }
}
