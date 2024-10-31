/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.model.impl.DefinitionField;
import gov.nist.secauto.metaschema.databind.model.impl.InstanceModelFieldComplex;
import gov.nist.secauto.metaschema.databind.model.impl.InstanceModelFieldScalar;

import java.lang.reflect.Field;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IBoundInstanceModelField<ITEM> extends IBoundInstanceModelNamed<ITEM>, IFieldInstanceAbsolute {

  @Override
  IBoundDefinitionModelField<ITEM> getDefinition();

  /**
   * Create a new bound field instance.
   *
   * @param field
   *          the Java field the instance is bound to
   * @param containingDefinition
   *          the definition containing the instance
   * @return the new instance
   */
  @NonNull
  static IBoundInstanceModelField<?> newInstance(
      @NonNull Field field,
      @NonNull IBoundDefinitionModelAssembly containingDefinition) {
    Class<?> itemType = IBoundInstanceModel.getItemType(field);

    IBoundInstanceModelField<?> retval;
    if (IBoundObject.class.isAssignableFrom(itemType)) {
      IBindingContext bindingContext = containingDefinition.getBindingContext();
      IBoundDefinitionModel<?> definition = bindingContext.getBoundDefinitionForClass(
          ObjectUtils.notNull(itemType.asSubclass(IBoundObject.class)));
      if (definition == null) {
        throw new IllegalStateException(String.format(
            "The field '%s' on class '%s' is not bound to a Metaschema field",
            field.toString(),
            field.getDeclaringClass().getName()));
      }
      retval = InstanceModelFieldComplex.newInstance(field, (DefinitionField) definition, containingDefinition);
    } else {

      retval = InstanceModelFieldScalar.newInstance(field, containingDefinition);
    }
    return retval;
  }

  @Override
  default boolean canHandleXmlQName(QName qname) {
    boolean retval;
    if (isEffectiveValueWrappedInXml()) {
      retval = qname.equals(getXmlQName());
    } else {
      IDataTypeAdapter<?> adapter = getDefinition().getJavaTypeAdapter();
      // we are to parse the data type
      retval = adapter.canHandleQName(qname);
    }
    return retval;
  }
}
