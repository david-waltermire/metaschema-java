/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.IModuleLoader;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.databind.IBindingContext.IBindingMatcher;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.binding.metaschema.MetaschemaModelModule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import edu.umd.cs.findbugs.annotations.NonNull;

public class PostProcessingModuleLoaderStrategy
    implements IBindingContext.IModuleLoaderStrategy {
  @NonNull
  private final List<IModuleLoader.IModulePostProcessor> modulePostProcessors;
  // private final Set<IModule> resolvedModules = new HashSet<>();
  // private final Lock resolvedModulesLock = new ReentrantLock();
  private final IBindingContext.IModuleLoaderStrategy delegate;
  private final Set<IModule> postProcessedModules = new HashSet<>();
  private final Lock postProcessedModulesLock = new ReentrantLock();

  public PostProcessingModuleLoaderStrategy(
      @NonNull List<IModuleLoader.IModulePostProcessor> modulePostProcessors) {
    this(modulePostProcessors, new SimpleModuleLoaderStrategy());
  }

  public PostProcessingModuleLoaderStrategy(
      @NonNull List<IModuleLoader.IModulePostProcessor> modulePostProcessors,
      @NonNull IBindingContext.IModuleLoaderStrategy delegate) {
    this.modulePostProcessors = CollectionUtil.unmodifiableList(new ArrayList<>(modulePostProcessors));
    this.delegate = delegate;
  }

  @NonNull
  protected List<IModuleLoader.IModulePostProcessor> getModulePostProcessors() {
    return modulePostProcessors;
  }

  @Override
  public IBoundModule loadModule(Class<? extends IBoundModule> clazz, IBindingContext bindingContext) {
    return delegate.loadModule(clazz, bindingContext);
  }

  @Override
  public void postProcessModule(IModule module, IBindingContext bindingContext) {
    processModule(module);
    delegate.postProcessModule(module, bindingContext);
  }

  @Override
  public IBoundModule registerModule(IModule module, IBindingContext bindingContext) {
    IBoundModule boundModule;
    postProcessedModulesLock.lock();
    try {
      // process before registering
      processModule(module);

      boundModule = delegate.registerModule(module, bindingContext);

      // ensure the resulting bound module is not processed again
      postProcessedModules.add(boundModule);
    } finally {
      postProcessedModulesLock.unlock();
    }
    return boundModule;
  }

  private void processModule(@NonNull IModule module) {
    postProcessedModulesLock.lock();
    try {
      if (!postProcessedModules.contains(module)) {
        // do not post-process the built-in Metaschema module, since it has already been
        // pre-processed
        if (!(module instanceof MetaschemaModelModule)) {
          for (IModuleLoader.IModulePostProcessor postProcessor : getModulePostProcessors()) {
            postProcessor.processModule(module);
          }
        }
        postProcessedModules.add(module);
      }
    } finally {
      postProcessedModulesLock.unlock();
    }
  }

  @Override
  public Collection<IBindingMatcher> getBindingMatchers() {
    return delegate.getBindingMatchers();
  }

  @Override
  public IBoundDefinitionModelComplex getBoundDefinitionForClass(
      Class<? extends IBoundObject> clazz,
      IBindingContext bindingContext) {

    //
    // resolvedModulesLock.lock();
    // try {
    // if (!resolvedModules.contains(module)) {
    // // add first, to avoid loops
    // resolvedModules.add(module);
    // for (IModuleLoader.IModulePostProcessor postProcessor :
    // getModulePostProcessors()) {
    // postProcessor.processModule(module);
    // }
    // }
    // } finally {
    // resolvedModulesLock.unlock();
    // }
    return delegate.getBoundDefinitionForClass(clazz, bindingContext);
  }
}
