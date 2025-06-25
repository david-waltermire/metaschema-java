
package gov.nist.secauto.metaschema.core.metapath.item.node;

import gov.nist.secauto.metaschema.core.metapath.item.node.IFeatureFlagContainerItem.FlagContainer;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFeatureModelContainerItem.ModelContainer;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IModelInstance;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.INamedModelInstance;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceGrouped;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.CouplingBetweenObjects")
final class DefaultNodeItemFactory
    extends AbstractNodeItemFactory {
  @NonNull
  static final DefaultNodeItemFactory SINGLETON = new DefaultNodeItemFactory();

  /**
   * Get the singleton instance of this node factory.
   *
   * @return the node factory instance
   */
  @NonNull
  public static DefaultNodeItemFactory instance() {
    return SINGLETON;
  }

  private DefaultNodeItemFactory() {
    // prevent construction
  }

  @Override
  @NonNull
  public Supplier<FlagContainer> newDataModelSupplier(@NonNull IFieldNodeItem item) {
    return () -> {
      Map<Integer, IFlagNodeItem> flags = generateFlags(item);
      return new FlagContainer(flags);
    };
  }

  @Override
  @NonNull
  public Supplier<ModelContainer> newDataModelSupplier(@NonNull IAssemblyNodeItem item) {
    return () -> {
      Map<Integer, IFlagNodeItem> flags = generateFlags(item);
      Map<Integer, List<? extends IModelNodeItem<?, ?>>> modelItems = generateModelItems(item);
      return new ModelContainer(flags, modelItems);
    };
  }

  @Override
  public Supplier<ModelContainer> newDataModelSupplier(IRootAssemblyNodeItem item) {
    return () -> {
      Map<Integer, List<? extends IModelNodeItem<?, ?>>> modelItems = CollectionUtil.singletonMap(
          item.getQName().getIndexPosition(),
          CollectionUtil.singletonList(item));
      return new ModelContainer(CollectionUtil.emptyMap(), modelItems);
    };
  }

  /**
   * Given the provided parent node item, generate a mapping of flag name to flag
   * node item for each flag on the parent assembly.
   *
   * @param parent
   *          the parent assembly containing flags
   * @return a mapping of flag name to flag item
   */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // need an ordered Map
  @NonNull
  protected Map<Integer, IFlagNodeItem> generateFlags(@NonNull IModelNodeItem<?, ?> parent) {
    Map<Integer, IFlagNodeItem> retval = new LinkedHashMap<>();

    Object parentValue = parent.getValue();
    assert parentValue != null;
    for (IFlagInstance instance : parent.getDefinition().getFlagInstances()) {
      Object flagValue = instance.getValue(parentValue);
      if (flagValue != null) {
        IFlagNodeItem item = newFlagNodeItem(instance, parent, flagValue);
        retval.put(instance.getQName().getIndexPosition(), item);
      }
    }
    return retval.isEmpty() ? CollectionUtil.emptyMap() : CollectionUtil.unmodifiableMap(retval);
  }

  /**
   * Given the provided parent node item, generate a mapping of model instance
   * name to model node item(s) for each model instance on the parent assembly.
   *
   * @param parent
   *          the parent assembly containing model instances
   * @return a mapping of model instance name to model node item(s)
   */
  @SuppressWarnings({ "PMD.UseConcurrentHashMap", "PMD.CognitiveComplexity" }) // need an ordered map
  @NonNull
  protected Map<Integer, List<? extends IModelNodeItem<?, ?>>> generateModelItems(
      @NonNull IAssemblyNodeItem parent) {
    Map<Integer, List<? extends IModelNodeItem<?, ?>>> retval = new LinkedHashMap<>();

    Object parentValue = parent.getValue();
    assert parentValue != null;
    for (IModelInstance instance : CollectionUtil.toIterable(getValuedModelInstances(parent.getDefinition()))) {
      if (instance instanceof INamedModelInstanceAbsolute) {
        INamedModelInstanceAbsolute namedInstance = (INamedModelInstanceAbsolute) instance;

        Object instanceValue = namedInstance.getValue(parentValue);
        if (instanceValue != null) {
          List<IModelNodeItem<?, ?>> items = generateModelInstanceItems(
              parent,
              namedInstance,
              ObjectUtils.notNull(namedInstance.getItemValues(instanceValue).stream()));
          retval.put(namedInstance.getQName().getIndexPosition(), items);
        }
      } else if (instance instanceof IChoiceGroupInstance) {
        IChoiceGroupInstance choiceInstance = (IChoiceGroupInstance) instance;

        Object instanceValue = choiceInstance.getValue(parentValue);
        if (instanceValue != null) {
          Map<INamedModelInstanceGrouped, List<Object>> instanceMap
              = choiceInstance.getItemValues(instanceValue).stream()
                  .map(item -> {
                    assert item != null;
                    INamedModelInstanceGrouped itemInstance = choiceInstance.getItemInstance(item);
                    return Map.entry(itemInstance, item);
                  })
                  .collect(Collectors.groupingBy(
                      Entry::getKey,
                      LinkedHashMap::new,
                      Collectors.mapping(Entry::getValue, Collectors.toUnmodifiableList())));

          for (Map.Entry<INamedModelInstanceGrouped, List<Object>> entry : instanceMap.entrySet()) {
            INamedModelInstanceGrouped namedInstance = entry.getKey();
            assert namedInstance != null;

            List<IModelNodeItem<?, ?>> items = generateModelInstanceItems(
                parent,
                namedInstance,
                ObjectUtils.notNull(entry.getValue().stream()));
            retval.put(namedInstance.getQName().getIndexPosition(), items);
          }
        }
      }

    }
    return retval.isEmpty() ? CollectionUtil.emptyMap() : CollectionUtil.unmodifiableMap(retval);
  }

  private List<IModelNodeItem<?, ?>> generateModelInstanceItems(
      @NonNull IAssemblyNodeItem parent,
      @NonNull INamedModelInstance namedInstance,
      @NonNull Stream<?> itemValues) {
    AtomicInteger index = new AtomicInteger();

    // the item values will be all non-null items
    return itemValues.map(itemValue -> {
      assert itemValue != null;
      return newModelItem(namedInstance, parent, index.incrementAndGet(), itemValue);
    }).collect(Collectors.toUnmodifiableList());
  }

  @Override
  public Supplier<ModelContainer> newMetaschemaModelSupplier(@NonNull IModuleNodeItem item) {
    return () -> {
      IModule module = item.getModule();

      // build flags from Metaschema definitions
      Map<Integer, IFlagNodeItem> flags = ObjectUtils.notNull(
          Collections.unmodifiableMap(module.getExportedFlagDefinitions().stream()
              .map(def -> newFlagNodeItem(ObjectUtils.notNull(def), item))
              .collect(
                  Collectors.toMap(
                      flag -> flag.getQName().getIndexPosition(),
                      Function.identity(),
                      (v1, v2) -> v2,
                      LinkedHashMap::new))));

      // build model items from Metaschema definitions
      Stream<IFieldNodeItem> fieldStream = module.getExportedFieldDefinitions().stream()
          .map(def -> newFieldNodeItem(ObjectUtils.notNull(def), item));
      Stream<IAssemblyNodeItem> assemblyStream = module.getExportedAssemblyDefinitions().stream()
          .map(def -> newAssemblyNodeItem(ObjectUtils.notNull(def), item));

      Map<Integer, List<? extends IModelNodeItem<?, ?>>> modelItems
          = ObjectUtils.notNull(Stream.concat(fieldStream, assemblyStream)
              .collect(
                  Collectors.collectingAndThen(
                      Collectors.groupingBy(model -> model.getQName().getIndexPosition()),
                      Collections::unmodifiableMap)));
      return new ModelContainer(flags, modelItems);
    };
  }

  @Override
  public Supplier<FlagContainer> newMetaschemaModelSupplier(@NonNull IFieldNodeItem item) {
    return () -> {
      Map<Integer, IFlagNodeItem> flags = generateMetaschemaFlags(item);
      return new FlagContainer(flags);
    };
  }

  @Override
  public Supplier<ModelContainer> newMetaschemaModelSupplier(
      @NonNull IAssemblyNodeItem item) {
    return () -> {
      Map<Integer, IFlagNodeItem> flags = generateMetaschemaFlags(item);
      Map<Integer, List<? extends IModelNodeItem<?, ?>>> modelItems = generateMetaschemaModelItems(item);
      return new ModelContainer(flags, modelItems);
    };
  }

  @NonNull
  protected Map<Integer, IFlagNodeItem> generateMetaschemaFlags(
      @NonNull IModelNodeItem<?, ?> parent) {
    Map<Integer, IFlagNodeItem> retval = new LinkedHashMap<>(); // NOPMD - intentional

    for (IFlagInstance instance : parent.getDefinition().getFlagInstances()) {
      assert instance != null;
      IFlagNodeItem item = newFlagNodeItem(instance, parent);
      retval.put(instance.getQName().getIndexPosition(), item);
    }
    return retval.isEmpty() ? CollectionUtil.emptyMap() : CollectionUtil.unmodifiableMap(retval);
  }

  @NonNull
  protected Map<Integer, List<? extends IModelNodeItem<?, ?>>> generateMetaschemaModelItems(
      @NonNull IAssemblyNodeItem parent) {
    Map<Integer, List<? extends IModelNodeItem<?, ?>>> retval = new LinkedHashMap<>(); // NOPMD - intentional

    for (INamedModelInstance instance : CollectionUtil.toIterable(getNamedModelInstances(parent.getDefinition()))) {
      assert instance != null;
      IModelNodeItem<?, ?> item = newModelItem(instance, parent);
      retval.put(instance.getQName().getIndexPosition(), Collections.singletonList(item));
    }
    return retval.isEmpty() ? CollectionUtil.emptyMap() : CollectionUtil.unmodifiableMap(retval);
  }

  @Override
  public IAssemblyNodeItem newAssemblyNodeItem(IAssemblyInstanceGrouped instance, IAssemblyNodeItem parent,
      int position, Object value) {
    throw new UnsupportedOperationException("implement");
  }
}
