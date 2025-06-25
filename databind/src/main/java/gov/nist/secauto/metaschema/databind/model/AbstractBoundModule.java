/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.AbstractModule;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.annotations.NsBinding;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public abstract class AbstractBoundModule
    extends AbstractModule<
        IBoundModule,
        IBoundDefinitionModelComplex,
        IBoundDefinitionFlag,
        IBoundDefinitionModelField<?>,
        IBoundDefinitionModelAssembly>
    implements IBoundModule {
  @NonNull
  private final IBindingContext bindingContext;
  @NonNull
  private final Lazy<Map<Integer, IBoundDefinitionModelAssembly>> assemblyDefinitions;
  @NonNull
  private final Lazy<Map<Integer, IBoundDefinitionModelField<?>>> fieldDefinitions;
  @NonNull
  private final Lazy<StaticContext> staticContext;
  @NonNull
  private final ISource source;

  /**
   * Construct a new Module instance.
   *
   * @param importedModules
   *          Module imports associated with the Metaschema module
   * @param bindingContext
   *          the Module binding context
   */
  protected AbstractBoundModule(
      @NonNull List<? extends IBoundModule> importedModules,
      @NonNull IBindingContext bindingContext) {
    super(importedModules);
    this.bindingContext = bindingContext;
    this.assemblyDefinitions = ObjectUtils.notNull(Lazy.of(() -> Arrays.stream(getAssemblyClasses())
        .map(clazz -> {
          assert clazz != null;
          return (IBoundDefinitionModelAssembly) ObjectUtils
              .requireNonNull(bindingContext.getBoundDefinitionForClass(clazz));
        })
        .collect(Collectors.toUnmodifiableMap(
            def -> def.getDefinitionQName().getIndexPosition(),
            Function.identity()))));
    this.fieldDefinitions = ObjectUtils.notNull(Lazy.of(() -> Arrays.stream(getFieldClasses())
        .map(clazz -> {
          assert clazz != null;
          return (IBoundDefinitionModelField<?>) ObjectUtils
              .requireNonNull(bindingContext.getBoundDefinitionForClass(clazz));
        })
        .collect(Collectors.toUnmodifiableMap(
            def -> def.getDefinitionQName().getIndexPosition(),
            Function.identity()))));
    this.staticContext = ObjectUtils.notNull(Lazy.of(() -> {
      StaticContext.Builder builder = StaticContext.builder()
          .defaultModelNamespace(getXmlNamespace());

      getNamespaceBindings()
          .forEach(
              (prefix, ns) -> builder.namespace(
                  ObjectUtils.requireNonNull(prefix),
                  ObjectUtils.requireNonNull(ns)));
      return builder.build();
    }));
    this.source = ISource.moduleSource(this);
  }

  @Override
  public ISource getSource() {
    return source;
  }

  @Override
  public String getLocationHint() {
    return ObjectUtils.notNull(getClass().getName());
  }

  @Override
  public StaticContext getModuleStaticContext() {
    return ObjectUtils.notNull(staticContext.get());
  }

  @Override
  @NonNull
  public IBindingContext getBindingContext() {
    return bindingContext;
  }

  @Override
  public Map<String, String> getNamespaceBindings() {
    return ObjectUtils.notNull(Arrays.stream(getNsBindings())
        .collect(Collectors.toMap(
            NsBinding::prefix,
            NsBinding::uri,
            (v1, v2) -> v2,
            LinkedHashMap::new)));
  }

  @SuppressWarnings({ "null" })
  @NonNull
  protected NsBinding[] getNsBindings() {
    return getClass().isAnnotationPresent(MetaschemaModule.class)
        ? getClass().getAnnotation(MetaschemaModule.class).nsBindings()
        : (NsBinding[]) Array.newInstance(NsBinding.class, 0);
  }

  /**
   * Get the assembly instance annotations associated with this bound choice
   * group.
   *
   * @return the annotations
   */
  @SuppressWarnings({ "null", "unchecked" })
  @NonNull
  protected Class<? extends IBoundObject>[] getAssemblyClasses() {
    return getClass().isAnnotationPresent(MetaschemaModule.class)
        ? getClass().getAnnotation(MetaschemaModule.class).assemblies()
        : (Class<? extends IBoundObject>[]) Array.newInstance(Class.class, 0);
  }

  /**
   * Get the field instance annotations associated with this bound choice group.
   *
   * @return the annotations
   */
  @SuppressWarnings({ "null", "unchecked" })
  @NonNull
  protected Class<? extends IBoundObject>[] getFieldClasses() {
    return getClass().isAnnotationPresent(MetaschemaModule.class)
        ? getClass().getAnnotation(MetaschemaModule.class).fields()
        : (Class<? extends IBoundObject>[]) Array.newInstance(Class.class, 0);
  }

  /**
   * Get the mapping of assembly definition effective name to definition.
   *
   * @return the mapping
   */
  protected Map<Integer, IBoundDefinitionModelAssembly> getAssemblyDefinitionMap() {
    return assemblyDefinitions.get();
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IBoundDefinitionModelAssembly> getAssemblyDefinitions() {
    return getAssemblyDefinitionMap().values();
  }

  @Override
  public IBoundDefinitionModelAssembly getAssemblyDefinitionByName(@NonNull Integer name) {
    return getAssemblyDefinitionMap().get(name);
  }

  /**
   * Get the mapping of field definition effective name to definition.
   *
   * @return the mapping
   */
  protected Map<Integer, IBoundDefinitionModelField<?>> getFieldDefinitionMap() {
    return fieldDefinitions.get();
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IBoundDefinitionModelField<?>> getFieldDefinitions() {
    return getFieldDefinitionMap().values();
  }

  @Override
  public IBoundDefinitionModelField<?> getFieldDefinitionByName(@NonNull Integer name) {
    return getFieldDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IBoundDefinitionFlag> getFlagDefinitions() {
    // Flags are always inline, so they do not have separate definitions
    return Collections.emptyList();
  }

  @Override
  public IBoundDefinitionFlag getFlagDefinitionByName(@NonNull IEnhancedQName name) {
    // Flags are always inline, so they do not have separate definitions
    return null;
  }
}
