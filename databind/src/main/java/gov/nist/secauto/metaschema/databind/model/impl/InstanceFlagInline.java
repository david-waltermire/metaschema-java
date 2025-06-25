/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractInlineFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModel;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.JsonFieldValueKeyFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.JsonKey;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.annotations.ValueConstraints;

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
 * Implements a Metaschema module inline flag instance/definition bound to a
 * Java field.
 */
public class InstanceFlagInline
    extends AbstractInlineFlagDefinition<IBoundDefinitionModel<IBoundObject>, IBoundDefinitionFlag, IBoundInstanceFlag>
    implements IBoundInstanceFlag {
  @NonNull
  private final Field javaField;
  @NonNull
  private final BoundFlag annotation;
  @NonNull
  private final IDataTypeAdapter<?> javaTypeAdapter;
  @Nullable
  private final Object defaultValue;
  @NonNull
  private final Lazy<IValueConstrained> constraints;
  @NonNull
  private final Lazy<Map<IAttributable.Key, Set<String>>> properties;

  /**
   * Construct a new inline field instance/definition.
   *
   * @param javaField
   *          the Java field bound to this instance
   * @param parent
   *          the definition containing this instance
   */
  public InstanceFlagInline(
      @NonNull Field javaField,
      @NonNull IBoundDefinitionModel<IBoundObject> parent) {
    super(parent);
    FieldSupport.bindField(javaField);
    this.javaField = javaField;
    this.annotation = ModelUtil.getAnnotation(javaField, BoundFlag.class);
    Class<? extends IDataTypeAdapter<?>> adapterClass = ObjectUtils.notNull(getAnnotation().typeAdapter());
    this.javaTypeAdapter = ModelUtil.getDataTypeAdapter(
        adapterClass,
        parent.getBindingContext());
    this.defaultValue = ModelUtil.resolveDefaultValue(getAnnotation().defaultValue(), this.javaTypeAdapter);

    IModule module = parent.getContainingModule();
    ISource source = module.getSource();

    this.constraints = ObjectUtils.notNull(Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      ValueConstraints valueAnnotation = getAnnotation().valueConstraints();
      ConstraintSupport.parse(valueAnnotation, source, retval);
      return retval;
    }));
    this.properties = ObjectUtils.notNull(
        Lazy.of(() -> CollectionUtil.unmodifiableMap(ObjectUtils.notNull(
            Arrays.stream(annotation.properties())
                .map(ModelUtil::toPropertyEntry)
                .collect(
                    Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v2, LinkedHashMap::new))))));
  }

  /**
   * Get the bound Java field.
   *
   * @return the bound Java field
   */
  @Override
  @NonNull
  public Field getField() {
    return javaField;
  }

  /**
   * Get the binding Java annotation.
   *
   * @return the binding Java annotation
   */
  @NonNull
  private BoundFlag getAnnotation() {
    return annotation;
  }

  @Override
  public IBoundModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  // ------------------------------------------
  // - Start annotation driven code - CPD-OFF -
  // ------------------------------------------

  @SuppressWarnings("null")
  @Override
  @NonNull
  public IValueConstrained getConstraintSupport() {
    return constraints.get();
  }

  @Override
  public boolean isRequired() {
    return getAnnotation().required();
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue;
  }

  @Override
  public boolean isJsonKey() {
    return getField().isAnnotationPresent(JsonKey.class);
  }

  @Override
  public boolean isJsonValueKey() {
    return getField().isAnnotationPresent(JsonFieldValueKeyFlag.class);
  }

  @Override
  public IDataTypeAdapter<?> getJavaTypeAdapter() {
    return javaTypeAdapter;
  }

  @Override
  @Nullable
  public String getFormalName() {
    return ModelUtil.resolveNoneOrValue(getAnnotation().formalName());
  }

  @Override
  @Nullable
  public MarkupLine getDescription() {
    return ModelUtil.resolveToMarkupLine(getAnnotation().description());
  }

  @Override
  public String getName() {
    return ObjectUtils.notNull(
        Optional.ofNullable(ModelUtil.resolveNoneOrValue(getAnnotation().name())).orElse(getField().getName()));
  }

  @Override
  public Integer getUseIndex() {
    return getAnnotation().useIndex();
  }

  @Override
  public Map<Key, Set<String>> getProperties() {
    return ObjectUtils.notNull(properties.get());
  }

  @Override
  @Nullable
  public MarkupMultiline getRemarks() {
    return ModelUtil.resolveToMarkupMultiline(getAnnotation().remarks());
  }

  // ----------------------------------------
  // - End annotation driven code - CPD-OFF -
  // ----------------------------------------
}
