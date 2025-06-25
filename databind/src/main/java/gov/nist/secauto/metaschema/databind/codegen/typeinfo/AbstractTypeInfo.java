/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.codegen.typeinfo;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.codegen.ClassUtils;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.def.IDefinitionTypeInfo;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

abstract class AbstractTypeInfo<PARENT extends IDefinitionTypeInfo> implements ITypeInfo {
  @NonNull
  private final PARENT parentDefinition;
  private final Lazy<String> propertyName;
  private final Lazy<String> fieldName;

  protected AbstractTypeInfo(@NonNull PARENT parentDefinition) {
    this.parentDefinition = parentDefinition;
    this.propertyName = Lazy.of(() -> {
      String baseName = ClassUtils.toPropertyName(getBaseName());
      IDefinitionTypeInfo parent = getParentTypeInfo();

      // first check if a property already exists with the same name
      return parent.getTypeResolver().getPropertyName(parent, baseName);
    });
    this.fieldName = Lazy.of(() -> "_" + ClassUtils.toVariableName(getPropertyName()));
  }

  @Override
  @NonNull
  public PARENT getParentTypeInfo() {
    return parentDefinition;
  }

  /**
   * The property name of the instance, which must be unique within the class.
   *
   * @return the name
   */
  @Override
  @NonNull
  public String getPropertyName() {
    return ObjectUtils.notNull(propertyName.get());
  }

  /**
   * Gets the name of the Java field for this property item.
   *
   * @return the Java field name
   */
  @Override
  @NonNull
  public final String getJavaFieldName() {
    return ObjectUtils.notNull(fieldName.get());
  }
}
