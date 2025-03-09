/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IContainerFlagSupport;
import gov.nist.secauto.metaschema.core.model.IFeatureDefinitionInstanceInlined;
import gov.nist.secauto.metaschema.core.model.IModelElementVisitor;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.info.IFeatureScalarItemValueHandler;
import gov.nist.secauto.metaschema.databind.model.info.IItemReadHandler;
import gov.nist.secauto.metaschema.databind.model.info.IItemWriteHandler;

import java.io.IOException;

public interface IBoundInstanceModelFieldScalar
    extends IBoundInstanceModelField<Object>,
    IBoundDefinitionModelField<Object>, IFeatureScalarItemValueHandler,
    IFeatureDefinitionInstanceInlined<IBoundDefinitionModelField<Object>, IBoundInstanceModelFieldScalar> {

  // integrate above
  @Override
  default IBoundDefinitionModelField<Object> getDefinition() {
    return IFeatureDefinitionInstanceInlined.super.getDefinition();
  }

  @Override
  default boolean isInline() {
    return IFeatureDefinitionInstanceInlined.super.isInline();
  }

  @Override
  default IBoundInstanceModelFieldScalar getInlineInstance() {
    return IFeatureDefinitionInstanceInlined.super.getInlineInstance();
  }

  @Override
  IBoundDefinitionModelAssembly getContainingDefinition();

  @Override
  default IContainerFlagSupport<IBoundInstanceFlag> getFlagContainer() {
    return IContainerFlagSupport.empty();
  }

  @Override
  default IBoundInstanceFlag getJsonKey() {
    // no flags
    return null;
  }

  @Override
  default IBoundInstanceFlag getItemJsonKey(Object item) {
    // no flags, no JSON key
    return null;
  }

  @Override
  default Object getFieldValue(Object item) {
    // the item is the field value
    return item;
  }

  @Override
  default String getJsonValueKeyName() {
    // no bound value, no value key name
    return null;
  }

  @Override
  default IBoundInstanceFlag getJsonValueKeyFlagInstance() {
    // no bound value, no value key name
    return null;
  }

  @Override
  default Object readItem(IBoundObject parent, IItemReadHandler handler) throws IOException {
    return handler.readItemField(ObjectUtils.requireNonNull(parent, "parent"), this);
  }

  @Override
  default void writeItem(Object item, IItemWriteHandler handler) throws IOException {
    handler.writeItemField(item, this);
  }

  @Override
  default <CONTEXT, RESULT> RESULT accept(IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return IBoundInstanceModelField.super.accept(visitor, context);
  }
}
