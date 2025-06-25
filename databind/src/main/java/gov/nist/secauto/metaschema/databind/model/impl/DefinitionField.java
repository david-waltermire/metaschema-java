/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.AssemblyConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IModelConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.io.BindingException;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelFieldComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundFieldValue;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.IBoundProperty;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFieldValue;
import gov.nist.secauto.metaschema.databind.model.annotations.Ignore;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaField;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.annotations.ValueConstraints;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Implements a Metaschema module global field definition bound to a Java class.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class DefinitionField
    extends AbstractBoundDefinitionModelComplex<MetaschemaField>
    implements IBoundDefinitionModelFieldComplex {
  @NonNull
  private final FieldValue fieldValue;
  @Nullable
  private IBoundInstanceFlag jsonValueKeyFlagInstance;
  @NonNull
  private final Lazy<FlagContainerSupport> flagContainer;
  @NonNull
  private final Lazy<IValueConstrained> constraints;
  @NonNull
  private final Lazy<Map<String, IBoundProperty<?>>> jsonProperties;
  @NonNull
  private final Lazy<Map<IAttributable.Key, Set<String>>> properties;

  /**
   * Collect all fields that are part of the model for this class.
   *
   * @param clazz
   *          the class
   * @return the field value instances if found or {@code null} otherwise
   */
  @Nullable
  private static Field getFieldValueField(Class<?> clazz) {
    Field[] fields = clazz.getDeclaredFields();

    Field retval = null;
    for (Field field : fields) {
      if (!field.isAnnotationPresent(BoundFieldValue.class) || field.isAnnotationPresent(Ignore.class)) {
        // skip this field, since it is ignored
        continue;
      }
      retval = field;
    }

    if (retval == null) {
      Class<?> superClass = clazz.getSuperclass();
      if (superClass != null) {
        // get instances from superclass
        retval = getFieldValueField(superClass);
      }
    }
    return retval;
  }

  /**
   * Construct a new Metaschema module field definition.
   *
   * @param clazz
   *          the Java class the definition is bound to
   * @param annotation
   *          the binding annotation associated with this class
   * @param module
   *          the module containing this class
   * @param bindingContext
   *          the Metaschema binding context managing this class used to lookup
   *          binding information
   * @return the instance
   */
  @NonNull
  public static DefinitionField newInstance(
      @NonNull Class<? extends IBoundObject> clazz,
      @NonNull MetaschemaField annotation,
      @NonNull IBoundModule module,
      @NonNull IBindingContext bindingContext) {
    return new DefinitionField(clazz, annotation, module, bindingContext);
  }

  private DefinitionField(
      @NonNull Class<? extends IBoundObject> clazz,
      @NonNull MetaschemaField annotation,
      @NonNull IBoundModule module,
      @NonNull IBindingContext bindingContext) {
    super(clazz, annotation, module, bindingContext);
    Field field = getFieldValueField(getBoundClass());
    if (field == null) {
      throw new IllegalArgumentException(
          String.format("Class '%s' is missing the '%s' annotation on one of its fields.",
              clazz.getName(),
              BoundFieldValue.class.getName()));
    }
    FieldSupport.bindField(field);
    this.fieldValue = new FieldValue(field, BoundFieldValue.class, bindingContext);
    this.flagContainer = ObjectUtils.notNull(Lazy.of(() -> new FlagContainerSupport(this, this::handleFlagInstance)));

    ISource source = module.getSource();

    this.constraints = ObjectUtils.notNull(Lazy.of(() -> {
      IModelConstrained retval = new AssemblyConstraintSet(source);
      ValueConstraints valueAnnotation = getAnnotation().valueConstraints();
      ConstraintSupport.parse(valueAnnotation, source, retval);
      return retval;
    }));
    this.jsonProperties = ObjectUtils.notNull(Lazy.of(() -> {
      IBoundInstanceFlag jsonValueKey = getJsonValueKeyFlagInstance();
      Predicate<IBoundInstanceFlag> flagFilter = jsonValueKey == null ? null : flag -> !flag.equals(jsonValueKey);
      return getJsonProperties(flagFilter);
    }));
    this.properties = ObjectUtils.notNull(
        Lazy.of(() -> CollectionUtil.unmodifiableMap(ObjectUtils.notNull(
            Arrays.stream(annotation.properties())
                .map(ModelUtil::toPropertyEntry)
                .collect(
                    Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v2, LinkedHashMap::new))))));
  }

  /**
   * A callback used to identify the JSON value key flag.
   *
   * @param instance
   *          a flag instance
   */
  protected void handleFlagInstance(@NonNull IBoundInstanceFlag instance) {
    if (instance.isJsonValueKey()) {
      this.jsonValueKeyFlagInstance = instance;
    }
  }

  @Override
  @NonNull
  public FieldValue getFieldValue() {
    return fieldValue;
  }

  @Override
  public IBoundInstanceFlag getJsonValueKeyFlagInstance() {
    // lazy load flags
    getFlagContainer();
    return jsonValueKeyFlagInstance;
  }

  @Override
  protected void deepCopyItemInternal(IBoundObject fromObject, IBoundObject toObject) throws BindingException {
    // copy the flags
    super.deepCopyItemInternal(fromObject, toObject);

    getFieldValue().deepCopy(fromObject, toObject);
  }

  // ------------------------------------------
  // - Start annotation driven code - CPD-OFF -
  // ------------------------------------------

  @Override
  @SuppressWarnings("null")
  @NonNull
  public FlagContainerSupport getFlagContainer() {
    return flagContainer.get();
  }

  @Override
  @NonNull
  public IValueConstrained getConstraintSupport() {
    return ObjectUtils.notNull(constraints.get());
  }

  @Override
  public Map<String, IBoundProperty<?>> getJsonProperties() {
    return ObjectUtils.notNull(jsonProperties.get());
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
  @NonNull
  public String getName() {
    return getAnnotation().name();
  }

  @Override
  public Map<Key, Set<String>> getProperties() {
    return ObjectUtils.notNull(properties.get());
  }

  @Override
  @Nullable
  public Integer getIndex() {
    return ModelUtil.resolveDefaultInteger(getAnnotation().index());
  }

  @Override
  @Nullable
  public MarkupMultiline getRemarks() {
    return ModelUtil.resolveToMarkupMultiline(getAnnotation().description());
  }

  /**
   * Implements a field definition value bound to a Java field.
   */
  protected class FieldValue
      implements IBoundFieldValue {
    @NonNull
    private final Field javaField;
    @NonNull
    private final BoundFieldValue annotation;
    @NonNull
    private final IDataTypeAdapter<?> javaTypeAdapter;
    @Nullable
    private final Object defaultValue;

    /**
     * Construct a new field value binding.
     *
     * @param javaField
     *          the Java field the field value is bound to
     * @param annotationClass
     *          the field value binding annotation Java class
     * @param bindingContext
     *          the Metaschema binding context managing this class
     */
    protected FieldValue(
        @NonNull Field javaField,
        @NonNull Class<BoundFieldValue> annotationClass,
        @NonNull IBindingContext bindingContext) {
      FieldSupport.bindField(javaField);
      this.javaField = javaField;
      this.annotation = ModelUtil.getAnnotation(javaField, annotationClass);
      this.javaTypeAdapter = ModelUtil.getDataTypeAdapter(
          this.annotation.typeAdapter(),
          bindingContext);
      this.defaultValue = ModelUtil.resolveDefaultValue(this.annotation.defaultValue(), this.javaTypeAdapter);
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
    public BoundFieldValue getAnnotation() {
      return annotation;
    }

    @Override
    public IBoundDefinitionModelFieldComplex getParentFieldDefinition() {
      return DefinitionField.this;
    }

    @Override
    public String getJsonValueKeyName() {
      String name = ModelUtil.resolveNoneOrValue(getAnnotation().valueKeyName());
      return name == null ? getJavaTypeAdapter().getDefaultJsonValueKey() : name;
    }

    @Override
    public String getJsonValueKeyFlagName() {
      return ModelUtil.resolveNoneOrValue(getAnnotation().valueKeyName());
    }

    @Override
    public Object getDefaultValue() {
      return defaultValue;
    }

    @Override
    public IDataTypeAdapter<?> getJavaTypeAdapter() {
      return javaTypeAdapter;
    }

    @Override
    public Object getEffectiveDefaultValue() {
      return getDefaultValue();
    }

    @Override
    public String getJsonName() {
      return getEffectiveJsonValueKeyName();
    }
  }
  // ----------------------------------------
  // - End annotation driven code - CPD-OFF -
  // ----------------------------------------
}
