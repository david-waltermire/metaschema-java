/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IFeatureDefinitionInstanceInlined;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IModelElementVisitor;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.io.BindingException;
import gov.nist.secauto.metaschema.databind.model.impl.InstanceFlagInline;
import gov.nist.secauto.metaschema.databind.model.info.IFeatureScalarItemValueHandler;
import gov.nist.secauto.metaschema.databind.model.info.IItemReadHandler;
import gov.nist.secauto.metaschema.databind.model.info.IItemWriteHandler;

import java.io.IOException;
import java.lang.reflect.Field;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a flag instance bound to Java data.
 */
public interface IBoundInstanceFlag
    extends IFlagInstance, IBoundDefinitionFlag,
    IFeatureScalarItemValueHandler,
    IBoundInstance<Object>,
    IFeatureDefinitionInstanceInlined<IBoundDefinitionFlag, IBoundInstanceFlag> {

  /**
   * Create a new bound flag instance.
   *
   * @param field
   *          the Java field the instance is bound to
   * @param containingDefinition
   *          the definition containing the instance
   * @return the new instance
   */
  @NonNull
  static IBoundInstanceFlag newInstance(
      @NonNull Field field,
      @NonNull IBoundDefinitionModel<IBoundObject> containingDefinition) {
    return new InstanceFlagInline(field, containingDefinition);
  }

  /**
   * Determines if this flag's value is used as the property name for the JSON
   * object that holds the remaining data based on this flag's containing
   * definition.
   *
   * @return {@code true} if this flag is used as a JSON key, or {@code false}
   *         otherwise
   */
  boolean isJsonKey();

  /**
   * Determines if this flag is used as a JSON "value key". A "value key" is a
   * flag who's value is used as the property name for the containing objects
   * value.
   *
   * @return {@code true} if the flag is used as a JSON "value key", or
   *         {@code false} otherwise
   */
  boolean isJsonValueKey();

  // Flag Instance Features
  // ======================

  @Override
  @NonNull
  IBoundDefinitionModel<IBoundObject> getContainingDefinition();

  @Override
  @NonNull
  default IBoundDefinitionModel<IBoundObject> getParentContainer() {
    return getContainingDefinition();
  }

  /**
   * {@inheritDoc}
   * <p>
   * For an inline instance, this instance is the definition.
   */
  @Override
  @NonNull
  IBoundDefinitionFlag getDefinition();

  @Override
  @NonNull
  default IBoundInstanceFlag getInlineInstance() {
    // always inline
    return this;
  }

  @Override
  default void deepCopy(@NonNull IBoundObject fromInstance, @NonNull IBoundObject toInstance) throws BindingException {
    Object value = getValue(fromInstance);
    if (value != null) {
      setValue(toInstance, deepCopyItem(value, toInstance));
    }
  }

  @Override
  @NonNull
  default Object readItem(IBoundObject parent, @NonNull IItemReadHandler handler) throws IOException {
    return handler.readItemFlag(ObjectUtils.requireNonNull(parent, "parent"), this);
  }

  @Override
  default void writeItem(Object item, IItemWriteHandler handler) throws IOException {
    handler.writeItemFlag(item, this);
  }

  @Override
  default boolean canHandleXmlQName(@NonNull IEnhancedQName qname) {
    return qname.equals(getQName());
  }

  @Override
  default <CONTEXT, RESULT> RESULT accept(IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return IFlagInstance.super.accept(visitor, context);
  }
}
