/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema;

import gov.nist.secauto.metaschema.core.configuration.IConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.model.AbstractModuleLoader;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.IBindingContext.IModuleLoaderStrategy;
import gov.nist.secauto.metaschema.databind.SimpleModuleLoaderStrategy;
import gov.nist.secauto.metaschema.databind.codegen.DefaultModuleBindingGenerator;
import gov.nist.secauto.metaschema.databind.io.DeserializationFeature;
import gov.nist.secauto.metaschema.databind.io.IBoundLoader;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.METASCHEMA;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.METASCHEMA.Import;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.MetaschemaModelModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.impl.BindingModule;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A module loader implementation that parses Metaschema modules from a
 * specified resource using the built-in model {@link MetaschemaModelModule}
 * binding.
 * <p>
 * Metaschema modules loaded this way are automatically registered with the
 * {@link IBindingContext}.
 * <p>
 * Use of this Metaschema module loader requires that the associated binding
 * context is initialized using a {@link IModuleLoaderStrategy} that supports
 * dynamic bound module loading. This can be accomplished using the
 * {@link SimpleModuleLoaderStrategy} initialized using the
 * {@link DefaultModuleBindingGenerator}.
 */
public class BindingModuleLoader
    extends AbstractModuleLoader<METASCHEMA, IBindingMetaschemaModule>
    implements IBindingModuleLoader {
  private final Lazy<IBoundLoader> loader;
  private final ModuleLoadingPostProcessor postProcessor;

  /**
   * Construct a new Metaschema loader.
   *
   * @param bindingContext
   *          the Metaschema binding context used to load bound resources
   * @param postProcessor
   *          the post processor to use when after loading a module
   */
  public BindingModuleLoader(
      @NonNull IBindingContext bindingContext,
      @NonNull ModuleLoadingPostProcessor postProcessor) {
    this.loader = Lazy.of(bindingContext::newBoundLoader);
    this.postProcessor = postProcessor;
  }

  @Override
  @NonNull
  public IBindingContext getBindingContext() {
    return getLoader().getBindingContext();
  }

  @Override
  protected IBindingMetaschemaModule newModule(
      URI resource,
      METASCHEMA binding,
      List<? extends IBindingMetaschemaModule> importedModules)
      throws MetaschemaException {
    IBindingContext bindingContext = getLoader().getBindingContext();

    IBindingMetaschemaModule module = new BindingModule(
        resource,
        ObjectUtils.notNull(
            (IBoundDefinitionModelAssembly) bindingContext.getBoundDefinitionForClass(METASCHEMA.class)),
        binding,
        importedModules);

    // post-process the module
    postProcessor.postProcessModule(module, bindingContext);
    return module;
  }

  @Override
  protected List<URI> getImports(METASCHEMA binding) {
    return ObjectUtils.notNull(binding.getImports().stream()
        .map(Import::getHref)
        .collect(Collectors.toUnmodifiableList()));
  }

  @Override
  protected METASCHEMA parseModule(URI resource) throws IOException {
    return getLoader().load(METASCHEMA.class, resource);
  }

  /**
   * Get the underlying bound loader.
   *
   * @return the loader
   */
  protected IBoundLoader getLoader() {
    return ObjectUtils.notNull(loader.get());
  }

  @Override
  public boolean isFeatureEnabled(DeserializationFeature<?> feature) {
    return getLoader().isFeatureEnabled(feature);
  }

  @Override
  public Map<DeserializationFeature<?>, Object> getFeatureValues() {
    return getLoader().getFeatureValues();
  }

  @Override
  public IMutableConfiguration<DeserializationFeature<?>>
      applyConfiguration(IConfiguration<DeserializationFeature<?>> other) {
    return getLoader().applyConfiguration(other);
  }

  @Override
  public IMutableConfiguration<DeserializationFeature<?>> set(DeserializationFeature<?> feature, Object value) {
    return getLoader().set(feature, value);
  }

  /**
   * Allow inline XML entities to be automatically replaced.
   */
  @Override
  public void allowEntityResolution() {
    enableFeature(DeserializationFeature.DESERIALIZE_XML_ALLOW_ENTITY_RESOLUTION);
  }
}
