/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.binding;

import gov.nist.secauto.metaschema.core.datatype.adapter.TokenAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultilineAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IMetaschemaData;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint;
import gov.nist.secauto.metaschema.databind.model.annotations.AllowedValue;
import gov.nist.secauto.metaschema.databind.model.annotations.AllowedValues;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFieldValue;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaField;
import gov.nist.secauto.metaschema.databind.model.annotations.ValueConstraints;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Any explanatory or helpful information to be provided about the remarks
 * parent.
 */
@SuppressWarnings({
    "PMD.FieldNamingConventions"
})
@MetaschemaField(
    formalName = "Remarks",
    description = "Any explanatory or helpful information to be provided about the remarks parent.",
    name = "remarks",
    moduleClass = MetaschemaModelModule.class)
public class Remarks implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  /**
   * "Mark as &lsquo;XML&rsquo; for XML-only or &lsquo;JSON&rsquo; for JSON-only
   * remarks."
   */
  @BoundFlag(
      formalName = "Remark Class",
      description = "Mark as 'XML' for XML-only or 'JSON' for JSON-only remarks.",
      name = "class",
      defaultValue = "ALL",
      typeAdapter = TokenAdapter.class,
      valueConstraints = @ValueConstraints(allowedValues = @AllowedValues(level = IConstraint.Level.ERROR,
          values = { @AllowedValue(value = "XML", description = "The remark applies to only XML representations."),
              @AllowedValue(value = "JSON", description = "The remark applies to only JSON and YAML representations."),
              @AllowedValue(value = "ALL", description = "The remark applies to all representations.") })))
  private String _clazz;

  @BoundFieldValue(
      valueKeyName = "remark",
      typeAdapter = MarkupMultilineAdapter.class)
  private MarkupMultiline _remark;

  public Remarks() {
    this(null);
  }

  public Remarks(IMetaschemaData data) {
    this.__metaschemaData = data;
  }

  @Override
  public IMetaschemaData getMetaschemaData() {
    return __metaschemaData;
  }

  public String getClazz() {
    return _clazz;
  }

  public void setClazz(String value) {
    _clazz = value;
  }

  public MarkupMultiline getRemark() {
    return _remark;
  }

  public void setRemark(MarkupMultiline value) {
    _remark = value;
  }

  @Override
  public String toString() {
    return new ReflectionToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE).toString();
  }
}
