/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractFieldInstance;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelFieldComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundFieldValue;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelFieldComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.IBoundProperty;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundField;
import gov.nist.secauto.metaschema.databind.model.annotations.GroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.info.IModelInstanceCollectionInfo;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Implements a Metaschema module field instance bound to a Java field,
 * supported by a bound definition class.
 */
public final class InstanceModelFieldComplex
    extends AbstractFieldInstance<
        IBoundDefinitionModelAssembly,
        IBoundDefinitionModelFieldComplex,
        IBoundInstanceModelFieldComplex,
        IBoundDefinitionModelAssembly>
    implements IBoundInstanceModelFieldComplex, IFeatureInstanceModelGroupAs {
  @NonNull
  private final Field javaField;
  @NonNull
  private final BoundField annotation;
  @NonNull
  private final Lazy<IModelInstanceCollectionInfo<IBoundObject>> collectionInfo;
  @NonNull
  private final IGroupAs groupAs;
  @NonNull
  private final DefinitionField definition;
  @NonNull
  private final Lazy<Object> defaultValue;
  @NonNull
  private final Lazy<Map<String, IBoundProperty<?>>> jsonProperties;
  @NonNull
  private final Lazy<Map<IAttributable.Key, Set<String>>> properties;

  /**
   * Construct a new field instance.
   *
   * @param javaField
   *          the Java field bound to this instance
   * @param definition
   *          the associated field definition
   * @param parent
   *          the definition containing this instance
   * @return the field instance
   */
  @NonNull
  public static InstanceModelFieldComplex newInstance(
      @NonNull Field javaField,
      @NonNull DefinitionField definition,
      @NonNull IBoundDefinitionModelAssembly parent) {
    BoundField annotation = ModelUtil.getAnnotation(javaField, BoundField.class);
    if (!annotation.inXmlWrapped()) {
      if (definition.hasChildren()) {
        throw new IllegalStateException(
            String.format("Field '%s' on class '%s' is requested to be unwrapped, but it has flags preventing this.",
                javaField.getName(),
                parent.getBoundClass().getName()));
      }
      if (!definition.getJavaTypeAdapter().isUnrappedValueAllowedInXml()) {
        throw new IllegalStateException(
            String.format(
                "Field '%s' on class '%s' is requested to be unwrapped, but its data type '%s' does not allow this.",
                javaField.getName(),
                parent.getBoundClass().getName(),
                definition.getJavaTypeAdapter().getPreferredName()));
      }
    }

    IGroupAs groupAs = ModelUtil.resolveDefaultGroupAs(
        annotation.groupAs(),
        parent.getContainingModule());
    if (annotation.maxOccurs() == -1 || annotation.maxOccurs() > 1) {
      if (IGroupAs.SINGLETON_GROUP_AS.equals(groupAs)) {
        throw new IllegalStateException(String.format("Field '%s' on class '%s' is missing the '%s' annotation.",
            javaField.getName(),
            javaField.getDeclaringClass().getName(),
            GroupAs.class.getName()));
      }
    } else if (!IGroupAs.SINGLETON_GROUP_AS.equals(groupAs)) {
      // max is 1 and a groupAs is set
      throw new IllegalStateException(
          String.format(
              "Field '%s' on class '%s' has the '%s' annotation, but maxOccurs=1. A groupAs must not be specfied.",
              javaField.getName(),
              javaField.getDeclaringClass().getName(),
              GroupAs.class.getName()));
    }
    return new InstanceModelFieldComplex(javaField, annotation, groupAs, definition, parent);
  }

  /**
   * Construct a new field instance bound to a Java field, supported by a bound
   * definition class.
   *
   * @param javaField
   *          the Java field bound to this instance
   * @param definition
   *          the assembly definition this instance is bound to
   * @param parent
   *          the definition containing this instance
   */
  @SuppressFBWarnings(value = "CT_CONSTRUCTOR_THROW", justification = "Use of final fields")
  private InstanceModelFieldComplex(
      @NonNull Field javaField,
      @NonNull BoundField annotation,
      @NonNull IGroupAs groupAs,
      @NonNull DefinitionField definition,
      @NonNull IBoundDefinitionModelAssembly parent) {
    super(parent);
    FieldSupport.bindField(javaField);
    this.javaField = javaField;
    this.annotation = annotation;
    this.collectionInfo = ObjectUtils.notNull(Lazy.of(() -> IModelInstanceCollectionInfo.of(this)));
    this.groupAs = groupAs;
    this.definition = definition;
    this.defaultValue = ObjectUtils.notNull(Lazy.of(() -> {
      Object retval = null;
      if (getMaxOccurs() == 1) {
        IBoundFieldValue fieldValue = definition.getFieldValue();

        Object fieldValueDefault = fieldValue.getDefaultValue();
        if (fieldValueDefault != null) {
          retval = newInstance(null);
          fieldValue.setValue(retval, fieldValueDefault);

          for (IBoundInstanceFlag flag : definition.getFlagInstances()) {
            assert flag != null;

            Object flagDefault = flag.getResolvedDefaultValue();
            if (flagDefault != null) {
              flag.setValue(retval, flagDefault);
            }
          }
        }
      }
      return retval;
    }));
    this.jsonProperties = ObjectUtils.notNull(Lazy.of(() -> {
      Predicate<IBoundInstanceFlag> flagFilter = null;
      IBoundInstanceFlag jsonKey = getEffectiveJsonKey();
      if (jsonKey != null) {
        flagFilter = flag -> !jsonKey.equals(flag);
      }
      return definition.getJsonProperties(flagFilter);
    }));
    this.properties = ObjectUtils.notNull(
        Lazy.of(() -> CollectionUtil.unmodifiableMap(ObjectUtils.notNull(
            Arrays.stream(annotation.properties())
                .map(ModelUtil::toPropertyEntry)
                .collect(
                    Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v2, LinkedHashMap::new))))));
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
  public BoundField getAnnotation() {
    return annotation;
  }

  @SuppressWarnings("null")
  @Override
  public IModelInstanceCollectionInfo<IBoundObject> getCollectionInfo() {
    return collectionInfo.get();
  }

  @Override
  public DefinitionField getDefinition() {
    return definition;
  }

  @Override
  public IBoundModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue.get();
  }

  @Override
  public Map<String, IBoundProperty<?>> getJsonProperties() {
    return ObjectUtils.notNull(jsonProperties.get());
  }

  @Override
  public IGroupAs getGroupAs() {
    return groupAs;
  }

  @Override
  public String getFormalName() {
    return ModelUtil.resolveNoneOrValue(getAnnotation().formalName());
  }

  @Override
  public MarkupLine getDescription() {
    return ModelUtil.resolveToMarkupLine(getAnnotation().description());
  }

  @Override
  public String getUseName() {
    return ModelUtil.resolveNoneOrValue(getAnnotation().useName());
  }

  @Override
  public Integer getUseIndex() {
    int value = getAnnotation().useIndex();
    return value == Integer.MIN_VALUE ? null : value;
  }

  @Override
  public boolean isInXmlWrapped() {
    return getAnnotation().inXmlWrapped();
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
  public Map<Key, Set<String>> getProperties() {
    return ObjectUtils.notNull(properties.get());
  }

  @Override
  public MarkupMultiline getRemarks() {
    return ModelUtil.resolveToMarkupMultiline(getAnnotation().remarks());
  }
}
