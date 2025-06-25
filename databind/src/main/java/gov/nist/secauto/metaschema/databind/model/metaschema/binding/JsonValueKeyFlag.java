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

@SuppressWarnings({
    "PMD.FieldNamingConventions"
})
@MetaschemaAssembly(
    formalName = "Flag Used as the Field Value's JSON Property Name",
    name = "json-value-key-flag",
    moduleClass = MetaschemaModelModule.class)
public class JsonValueKeyFlag implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  @BoundFlag(
      formalName = "Flag Reference",
      name = "flag-ref",
      required = true,
      typeAdapter = TokenAdapter.class)
  private String _flagRef;

  public JsonValueKeyFlag() {
    this(null);
  }

  public JsonValueKeyFlag(IMetaschemaData data) {
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
