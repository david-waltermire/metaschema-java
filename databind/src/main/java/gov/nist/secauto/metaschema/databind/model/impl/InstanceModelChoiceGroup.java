/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.model.AbstractChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.DefaultChoiceGroupModelBuilder;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IContainerModelSupport;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelChoiceGroup;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedField;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedNamed;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundChoiceGroup;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundGroupedField;
import gov.nist.secauto.metaschema.databind.model.annotations.GroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.info.IModelInstanceCollectionInfo;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Implements a Metaschema module choice group instance bound to a Java field.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class InstanceModelChoiceGroup
    extends AbstractChoiceGroupInstance<
        IBoundDefinitionModelAssembly,
        IBoundInstanceModelGroupedNamed,
        IBoundInstanceModelGroupedField,
        IBoundInstanceModelGroupedAssembly>
    implements IBoundInstanceModelChoiceGroup, IFeatureInstanceModelGroupAs {
  @NonNull
  private final Field javaField;
  @NonNull
  private final BoundChoiceGroup annotation;
  @NonNull
  private final Lazy<IModelInstanceCollectionInfo<IBoundObject>> collectionInfo;
  @NonNull
  private final IGroupAs groupAs;
  @NonNull
  private final Lazy<IContainerModelSupport<
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedField,
      IBoundInstanceModelGroupedAssembly>> modelContainer;
  @NonNull
  private final Lazy<Map<Class<?>, IBoundInstanceModelGroupedNamed>> classToInstanceMap;
  @NonNull
  private final Lazy<Map<IEnhancedQName, IBoundInstanceModelGroupedNamed>> qnameToInstanceMap;
  @NonNull
  private final Lazy<Map<String, IBoundInstanceModelGroupedNamed>> discriminatorToInstanceMap;

  /**
   * Construct a new Metaschema module choice group instance.
   *
   * @param javaField
   *          the Java field bound to this instance
   * @param parent
   *          the definition containing this instance
   * @return the instance
   */
  @NonNull
  public static InstanceModelChoiceGroup newInstance(
      @NonNull Field javaField,
      @NonNull IBoundDefinitionModelAssembly parent) {
    BoundChoiceGroup annotation = ModelUtil.getAnnotation(javaField, BoundChoiceGroup.class);
    IGroupAs groupAs = ModelUtil.resolveDefaultGroupAs(annotation.groupAs(), parent.getContainingModule());
    if (annotation.maxOccurs() == -1 || annotation.maxOccurs() > 1) {
      if (IGroupAs.SINGLETON_GROUP_AS.equals(groupAs)) {
        throw new IllegalStateException(String.format("Field '%s' on class '%s' is missing the '%s' annotation.",
            javaField.getName(),
            parent.getBoundClass().getName(),
            GroupAs.class.getName()));
      }
    } else if (!IGroupAs.SINGLETON_GROUP_AS.equals(groupAs)) {
      // max is 1 and a groupAs is set
      throw new IllegalStateException(
          String.format(
              "Field '%s' on class '%s' has the '%s' annotation, but maxOccurs=1. A groupAs must not be specfied.",
              javaField.getName(),
              parent.getBoundClass().getName(),
              GroupAs.class.getName()));
    }
    return new InstanceModelChoiceGroup(javaField, annotation, groupAs, parent);
  }

  @NonNull
  private static IContainerModelSupport<
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedField,
      IBoundInstanceModelGroupedAssembly> newContainerModel(
          @NonNull BoundGroupedAssembly[] assemblies,
          @NonNull BoundGroupedField[] fields,
          @NonNull IBoundInstanceModelChoiceGroup container) {
    DefaultChoiceGroupModelBuilder<
        IBoundInstanceModelGroupedNamed,
        IBoundInstanceModelGroupedField,
        IBoundInstanceModelGroupedAssembly> builder = new DefaultChoiceGroupModelBuilder<>();

    Arrays.stream(assemblies)
        .map(instance -> {
          assert instance != null;
          return IBoundInstanceModelGroupedAssembly.newInstance(instance, container);
        }).forEachOrdered(builder::append);
    Arrays.stream(fields)
        .map(instance -> {
          assert instance != null;
          return IBoundInstanceModelGroupedField.newInstance(instance, container);
        }).forEachOrdered(builder::append);

    return builder.buildChoiceGroup();
  }

  @SuppressFBWarnings(value = "CT_CONSTRUCTOR_THROW", justification = "Use of final fields")
  private InstanceModelChoiceGroup(
      @NonNull Field javaField,
      @NonNull BoundChoiceGroup annotation,
      @NonNull IGroupAs groupAs,
      @NonNull IBoundDefinitionModelAssembly parent) {
    super(parent);
    FieldSupport.bindField(javaField);
    this.javaField = javaField;
    this.annotation = annotation;
    this.groupAs = groupAs;
    this.collectionInfo = ObjectUtils.notNull(Lazy.of(() -> IModelInstanceCollectionInfo.of(this)));
    this.modelContainer = ObjectUtils.notNull(Lazy.of(() -> newContainerModel(
        this.annotation.assemblies(),
        this.annotation.fields(),
        this)));
    this.classToInstanceMap = ObjectUtils.notNull(Lazy.of(() -> Collections.unmodifiableMap(
        getNamedModelInstances().stream()
            .map(instance -> instance)
            .collect(Collectors.toMap(
                item -> item.getDefinition().getBoundClass(),
                CustomCollectors.identity())))));
    this.qnameToInstanceMap = ObjectUtils.notNull(Lazy.of(() -> Collections.unmodifiableMap(
        getNamedModelInstances().stream()
            .collect(Collectors.toMap(
                IBoundInstanceModelGroupedNamed::getQName,
                CustomCollectors.identity())))));
    this.discriminatorToInstanceMap = ObjectUtils.notNull(Lazy.of(() -> Collections.unmodifiableMap(
        getNamedModelInstances().stream()
            .collect(Collectors.toMap(
                IBoundInstanceModelGroupedNamed::getEffectiveDisciminatorValue,
                CustomCollectors.identity())))));
  }

  // ------------------------------------------
  // - Start annotation driven code - CPD-OFF -
  // ------------------------------------------

  @Override
  public Field getField() {
    return javaField;
  }

  /**
   * Get the binding Java annotation.
   *
   * @return the binding Java annotation
   */
  @NonNull
  public BoundChoiceGroup getAnnotation() {
    return annotation;
  }

  @SuppressWarnings("null")
  @Override
  public IModelInstanceCollectionInfo<IBoundObject> getCollectionInfo() {
    return collectionInfo.get();
  }

  /**
   * Get the mapping of XML qualified names bound to a distinct grouped model
   * instance.
   *
   * @return the mapping
   */
  @SuppressWarnings("null")
  @NonNull
  protected Map<IEnhancedQName, IBoundInstanceModelGroupedNamed> getQNameToInstanceMap() {
    return qnameToInstanceMap.get();
  }

  /**
   * Get the mapping of Java classes bound to a distinct grouped model instance.
   *
   * @return the mapping
   */
  @SuppressWarnings("null")
  @NonNull
  protected Map<Class<?>, IBoundInstanceModelGroupedNamed> getClassToInstanceMap() {
    return classToInstanceMap.get();
  }

  /**
   * Get the mapping of JSON discriminator values bound to a distinct grouped
   * model instance.
   *
   * @return the mapping
   */
  @SuppressWarnings("null")
  @NonNull
  protected Map<String, IBoundInstanceModelGroupedNamed> getDiscriminatorToInstanceMap() {
    return discriminatorToInstanceMap.get();
  }

  @Override
  @Nullable
  public IBoundInstanceModelGroupedNamed getGroupedModelInstance(@NonNull Class<?> clazz) {
    return getClassToInstanceMap().get(clazz);
  }

  @Override
  @Nullable
  public IBoundInstanceModelGroupedNamed getGroupedModelInstance(@NonNull IEnhancedQName name) {
    return getQNameToInstanceMap().get(name);
  }

  @Override
  public IBoundInstanceModelGroupedNamed getGroupedModelInstance(String discriminator) {
    return getDiscriminatorToInstanceMap().get(discriminator);
  }

  @Override
  public IGroupAs getGroupAs() {
    return groupAs;
  }

  @SuppressWarnings("null")
  @Override
  public IContainerModelSupport<
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedNamed,
      IBoundInstanceModelGroupedField,
      IBoundInstanceModelGroupedAssembly> getModelContainer() {
    return modelContainer.get();
  }

  @Override
  public IBoundDefinitionModelAssembly getOwningDefinition() {
    return getParentContainer();
  }

  @Override
  public IBoundModule getContainingModule() {
    return getOwningDefinition().getContainingModule();
  }

  @Override
  public int getMinOccurs() {
    return getAnnotation().minOccurs();
  }

  @Override
  public int getMaxOccurs() {
    return getAnnotation().maxOccurs();
  }

  @Override
  public String getJsonDiscriminatorProperty() {
    return getAnnotation().discriminator();
  }

  @Override
  public String getJsonKeyFlagInstanceName() {
    return getAnnotation().jsonKey();
  }

  @Override
  public IBoundInstanceFlag getItemJsonKey(Object item) {
    String jsonKeyFlagName = getJsonKeyFlagInstanceName();
    IBoundInstanceFlag retval = null;

    if (jsonKeyFlagName != null) {
      Class<?> clazz = item.getClass();

      IBoundInstanceModelGroupedNamed itemInstance = getClassToInstanceMap().get(clazz);
      String namespace = itemInstance.getQName().getNamespace();
      retval = itemInstance.getDefinition().getFlagInstanceByName(IEnhancedQName.of(namespace, jsonKeyFlagName)
          .getIndexPosition());
    }
    return retval;
  }
}
