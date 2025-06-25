/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Provides a common, abstract implementation of a {@link IModule}.
 *
 * @param <M>
 *          the imported module Java type
 * @param <D>
 *          the definition Java type
 * @param <FL>
 *          the flag definition Java type
 * @param <FI>
 *          the field definition Java type
 * @param <A>
 *          the assembly definition Java type
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public abstract class AbstractModule<
    M extends IModuleExtended<M, D, FL, FI, A>,
    D extends IModelDefinition,
    FL extends IFlagDefinition,
    FI extends IFieldDefinition,
    A extends IAssemblyDefinition>
    implements IModuleExtended<M, D, FL, FI, A> {
  private static final Logger LOGGER = LogManager.getLogger(AbstractModule.class);

  @NonNull
  private final List<? extends M> importedModules;
  @NonNull
  private final Lazy<Exports> exports;
  @NonNull
  private final Lazy<IEnhancedQName> qname;

  /**
   * Construct a new Metaschema module object.
   *
   * @param importedModules
   *          the collection of Metaschema module objects this Metaschema module
   *          imports
   */
  public AbstractModule(@NonNull List<? extends M> importedModules) {
    this.importedModules
        = CollectionUtil.unmodifiableList(ObjectUtils.requireNonNull(importedModules, "importedModules"));
    this.exports = ObjectUtils.notNull(Lazy.of(() -> new Exports(importedModules)));
    this.qname = ObjectUtils.notNull(Lazy.of(() -> IEnhancedQName.of(getXmlNamespace(), getShortName())));
  }

  @Override
  public IEnhancedQName getQName() {
    return ObjectUtils.notNull(qname.get());
  }

  @Override
  @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "interface doesn't allow modification")
  public List<? extends M> getImportedModules() {
    return importedModules;
  }

  @SuppressWarnings("null")
  @NonNull
  private Exports getExports() {
    return exports.get();
  }

  private Map<String, ? extends M> getImportedModulesByShortName() {
    return importedModules.stream().collect(Collectors.toMap(IModule::getShortName, Function.identity()));
  }

  @Override
  public M getImportedModuleByShortName(String name) {
    return getImportedModulesByShortName().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<FL> getExportedFlagDefinitions() {
    return getExports().getExportedFlagDefinitionMap().values();
  }

  @Override
  public FL getExportedFlagDefinitionByName(IEnhancedQName name) {
    return getExports().getExportedFlagDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<FI> getExportedFieldDefinitions() {
    return getExports().getExportedFieldDefinitionMap().values();
  }

  @Override
  public FI getExportedFieldDefinitionByName(Integer name) {
    return getExports().getExportedFieldDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<A> getExportedAssemblyDefinitions() {
    return getExports().getExportedAssemblyDefinitionMap().values();
  }

  @Override
  public A getExportedAssemblyDefinitionByName(Integer name) {
    return getExports().getExportedAssemblyDefinitionMap().get(name);
  }

  @Override
  public A getExportedRootAssemblyDefinitionByName(Integer name) {
    return getExports().getExportedRootAssemblyDefinitionMap().get(name);
  }

  @SuppressWarnings({ "unused" }) // used by lambda
  private static <DEF extends IDefinition> DEF handleShadowedDefinitions(
      @NonNull IEnhancedQName key,
      @NonNull DEF oldDef,
      @NonNull DEF newDef) {
    if (!oldDef.equals(newDef) && LOGGER.isWarnEnabled()) {
      LOGGER.warn("The {} '{}' from metaschema '{}' is shadowing '{}' from metaschema '{}'",
          newDef.getModelType().name().toLowerCase(Locale.ROOT),
          newDef.getName(),
          newDef.getContainingModule().getShortName(),
          oldDef.getName(),
          oldDef.getContainingModule().getShortName());
    }
    return newDef;
  }

  @SuppressWarnings({ "unused" }) // used by lambda
  private static <DEF extends IDefinition> DEF handleShadowedDefinitions(
      @NonNull Integer key,
      @NonNull DEF oldDef,
      @NonNull DEF newDef) {
    if (!oldDef.equals(newDef) && LOGGER.isWarnEnabled()) {
      LOGGER.warn("The {} '{}' from metaschema '{}' is shadowing '{}' from metaschema '{}'",
          newDef.getModelType().name().toLowerCase(Locale.ROOT),
          newDef.getName(),
          newDef.getContainingModule().getShortName(),
          oldDef.getName(),
          oldDef.getContainingModule().getShortName());
    }
    return newDef;
  }

  private class Exports {
    @NonNull
    private final Map<IEnhancedQName, FL> exportedFlagDefinitions;
    @NonNull
    private final Map<Integer, FI> exportedFieldDefinitions;
    @NonNull
    private final Map<Integer, A> exportedAssemblyDefinitions;
    @NonNull
    private final Map<Integer, A> exportedRootAssemblyDefinitions;

    @SuppressWarnings({ "PMD.ConstructorCallsOverridableMethod", "synthetic-access" })
    public Exports(@NonNull List<? extends M> importedModules) {
      // Populate the stream with the definitions from this module
      Predicate<IDefinition> filter = IModuleExtended.allNonLocalDefinitions();
      Stream<FL> flags = getFlagDefinitions().stream()
          .filter(filter);
      Stream<FI> fields = getFieldDefinitions().stream()
          .filter(filter);
      Stream<A> assemblies = getAssemblyDefinitions().stream()
          .filter(filter);

      // handle definitions from any included module
      if (!importedModules.isEmpty()) {
        Stream<FL> importedFlags = Stream.empty();
        Stream<FI> importedFields = Stream.empty();
        Stream<A> importedAssemblies = Stream.empty();

        for (M module : importedModules) {
          importedFlags = Stream.concat(importedFlags, module.getExportedFlagDefinitions().stream());
          importedFields = Stream.concat(importedFields, module.getExportedFieldDefinitions().stream());
          importedAssemblies
              = Stream.concat(importedAssemblies, module.getExportedAssemblyDefinitions().stream());
        }

        flags = Stream.concat(importedFlags, flags);
        fields = Stream.concat(importedFields, fields);
        assemblies = Stream.concat(importedAssemblies, assemblies);
      }

      // Build the maps. Definitions from this module will take priority, with
      // shadowing being reported when a definition from this module has the same name
      // as an imported one
      Map<IEnhancedQName, FL> exportedFlagDefinitions = flags.collect(
          CustomCollectors.toMap(
              IFlagDefinition::getDefinitionQName,
              CustomCollectors.identity(),
              AbstractModule::handleShadowedDefinitions));
      Map<Integer, FI> exportedFieldDefinitions = fields.collect(
          CustomCollectors.toMap(
              def -> def.getDefinitionQName().getIndexPosition(),
              CustomCollectors.identity(),
              AbstractModule::handleShadowedDefinitions));
      Map<Integer, A> exportedAssemblyDefinitions = assemblies.collect(
          CustomCollectors.toMap(
              def -> def.getDefinitionQName().getIndexPosition(),
              CustomCollectors.identity(),
              AbstractModule::handleShadowedDefinitions));

      this.exportedFlagDefinitions = exportedFlagDefinitions.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(exportedFlagDefinitions);
      this.exportedFieldDefinitions = exportedFieldDefinitions.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(exportedFieldDefinitions);
      this.exportedAssemblyDefinitions = exportedAssemblyDefinitions.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(exportedAssemblyDefinitions);
      this.exportedRootAssemblyDefinitions = exportedAssemblyDefinitions.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(ObjectUtils.notNull(exportedAssemblyDefinitions.values().stream()
              .filter(IAssemblyDefinition::isRoot)
              .collect(CustomCollectors.toMap(
                  def -> def.getRootQName().getIndexPosition(),
                  CustomCollectors.identity(),
                  AbstractModule::handleShadowedDefinitions))));
    }

    @NonNull
    public Map<IEnhancedQName, FL> getExportedFlagDefinitionMap() {
      return this.exportedFlagDefinitions;
    }

    @NonNull
    public Map<Integer, FI> getExportedFieldDefinitionMap() {
      return this.exportedFieldDefinitions;
    }

    @NonNull
    public Map<Integer, A> getExportedAssemblyDefinitionMap() {
      return this.exportedAssemblyDefinitions;
    }

    @NonNull
    public Map<Integer, A> getExportedRootAssemblyDefinitionMap() {
      return this.exportedRootAssemblyDefinitions;
    }
  }
}
