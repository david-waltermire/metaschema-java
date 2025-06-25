/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.binding;

import gov.nist.secauto.metaschema.core.datatype.adapter.StringAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IMetaschemaData;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaAssembly;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * A Metapath expression identifying the model node that the constraints will be
 * applied to.
 */
@SuppressWarnings({
    "PMD.FieldNamingConventions",
})
@MetaschemaAssembly(
    description = "A Metapath expression identifying the model node that the constraints will be applied to.",
    name = "metaschema-metapath",
    moduleClass = MetaschemaModelModule.class)
public class MetaschemaMetapath implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  @BoundFlag(
      name = "target",
      required = true,
      typeAdapter = StringAdapter.class)
  private String _target;

  public MetaschemaMetapath() {
    this(null);
  }

  public MetaschemaMetapath(IMetaschemaData data) {
    this.__metaschemaData = data;
  }

  @Override
  public IMetaschemaData getMetaschemaData() {
    return __metaschemaData;
  }

  public String getTarget() {
    return _target;
  }

  public void setTarget(String value) {
    _target = value;
  }

  @Override
  public String toString() {
    return new ReflectionToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE).toString();
  }
}
