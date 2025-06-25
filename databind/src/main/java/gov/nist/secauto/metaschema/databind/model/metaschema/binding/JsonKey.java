/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.binding;

import gov.nist.secauto.metaschema.core.datatype.adapter.TokenAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IMetaschemaData;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaAssembly;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Used in JSON (and similar formats) to identify a flag that will be used as
 * the property name in an object hold a collection of sibling objects. Requires
 * that siblings must never share <code>json-key</code> values.
 */
@SuppressWarnings({
    "PMD.FieldNamingConventions"
})
@MetaschemaAssembly(
    formalName = "JSON Key",
    description = "Used in JSON (and similar formats) to identify a flag that will be used as the property name in an object hold a collection of sibling objects. Requires that siblings must never share `json-key` values.",
    name = "json-key",
    moduleClass = MetaschemaModelModule.class)
public class JsonKey implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  /**
   * "References the flag that will serve as the JSON key."
   */
  @BoundFlag(
      formalName = "JSON Key Flag Reference",
      description = "References the flag that will serve as the JSON key.",
      name = "flag-ref",
      required = true,
      typeAdapter = TokenAdapter.class)
  private String _flagRef;

  public JsonKey() {
    this(null);
  }

  public JsonKey(IMetaschemaData data) {
    this.__metaschemaData = data;
  }

  @Override
  public IMetaschemaData getMetaschemaData() {
    return __metaschemaData;
  }

  public String getFlagRef() {
    return _flagRef;
  }

  public void setFlagRef(String value) {
    _flagRef = value;
  }

  @Override
  public String toString() {
    return new ReflectionToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE).toString();
  }
}
