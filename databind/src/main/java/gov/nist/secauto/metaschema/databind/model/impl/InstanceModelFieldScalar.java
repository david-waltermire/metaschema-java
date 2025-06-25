/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractInlineFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelField;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelFieldScalar;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundField;
import gov.nist.secauto.metaschema.databind.model.annotations.GroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.annotations.ValueConstraints;
import gov.nist.secauto.metaschema.databind.model.info.IModelInstanceCollectionInfo;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Implements a Metaschema module field instance bound to a scalar valued Java
 * field.
 */
public final class InstanceModelFieldScalar
    extends AbstractInlineFieldDefinition<
        IBoundDefinitionModelAssembly,
        IBoundDefinitionModelField<Object>,
        IBoundInstanceModelFieldScalar,
        IBoundDefinitionModelAssembly,
        IBoundInstanceFlag>
    implements IBoundInstanceModelFieldScalar, IFeatureInstanceModelGroupAs {
  @NonNull
  private final Field javaField;
  @NonNull
  private final BoundField annotation;
  @NonNull
  private final Lazy<IModelInstanceCollectionInfo<Object>> collectionInfo;
  @NonNull
  private final IGroupAs groupAs;
  @NonNull
  private final IDataTypeAdapter<?> javaTypeAdapter;
  @Nullable
  private final Object defaultValue;
  @NonNull
  private final Lazy<IValueConstrained> constraints;
  @NonNull
  private final Lazy<Map<IAttributable.Key, Set<String>>> properties;

  /**
   * Construct a new field instance bound to a Java field.
   *
   * @param javaField
   *          the Java field bound to this instance
   * @param parent
   *          the definition containing this instance
   * @return the instance
   */
  @NonNull
  public static InstanceModelFieldScalar newInstance(
      @NonNull Field javaField,
      @NonNull IBoundDefinitionModelAssembly parent) {
    BoundField annotation = ModelUtil.getAnnotation(javaField, BoundField.class);
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

    return new InstanceModelFieldScalar(
        javaField,
        annotation,
        groupAs,
        parent);
  }

  private InstanceModelFieldScalar(
      @NonNull Field javaField,
      @NonNull BoundField annotation,
      @NonNull IGroupAs groupAs,
      @NonNull IBoundDefinitionModelAssembly parent) {
    super(parent);
    FieldSupport.bindField(javaField);
    this.javaField = javaField;
    this.annotation = annotation;
    this.collectionInfo = ObjectUtils.notNull(Lazy.of(() -> IModelInstanceCollectionInfo.of(this)));
    this.groupAs = groupAs;
    this.javaTypeAdapter = ModelUtil.getDataTypeAdapter(
        annotation.typeAdapter(),
        parent.getBindingContext());
    this.defaultValue = ModelUtil.resolveDefaultValue(annotation.defaultValue(), this.javaTypeAdapter);

    IModule module = getContainingModule();
    ISource source = module.getSource();

    this.constraints = ObjectUtils.notNull(Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      ValueConstraints valueAnnotation = annotation.valueConstraints();
      ConstraintSupport.parse(valueAnnotation, module.getSource(), retval);
      return retval;
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
  public IBindingContext getBindingContext() {
    return getContainingDefinition().getBindingContext();
  }

  @Override
  public IBoundModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

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
  public IModelInstanceCollectionInfo<Object> getCollectionInfo() {
    return collectionInfo.get();
  }

  @SuppressWarnings("null")
  @Override
  @NonNull
  public IValueConstrained getConstraintSupport() {
    return constraints.get();
  }

  @Override
  public IDataTypeAdapter<?> getJavaTypeAdapter() {
    return javaTypeAdapter;
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue;
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

  @Override
  public String getName() {
    // the name is stored as a usename to remain consistent with non-scalar valued
    // fields
    return ObjectUtils.notNull(
        Optional.ofNullable(ModelUtil.resolveNoneOrValue(getAnnotation().useName())).orElse(getField().getName()));
  }

  // ----------------------------------------
  // - End annotation driven code - CPD-OFF -
  // ----------------------------------------
}
