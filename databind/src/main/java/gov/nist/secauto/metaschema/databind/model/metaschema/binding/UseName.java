/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.binding;

import gov.nist.secauto.metaschema.core.datatype.adapter.NonNegativeIntegerAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.TokenAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IMetaschemaData;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFieldValue;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaField;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.math.BigInteger;

/**
 * Allows the name of the definition to be overridden.
 */
@SuppressWarnings({
    "PMD.FieldNamingConventions"
})
@MetaschemaField(
    formalName = "Use Name",
    description = "Allows the name of the definition to be overridden.",
    name = "use-name",
    moduleClass = MetaschemaModelModule.class)
public class UseName implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  /**
   * "Used for binary formats instead of the textual name."
   */
  @BoundFlag(
      formalName = "Numeric Index",
      description = "Used for binary formats instead of the textual name.",
      name = "index",
      typeAdapter = NonNegativeIntegerAdapter.class)
  private BigInteger _index;

  @BoundFieldValue(
      valueKeyName = "name",
      typeAdapter = TokenAdapter.class)
  private String _name;

  public UseName() {
    this(null);
  }

  public UseName(IMetaschemaData data) {
    this.__metaschemaData = data;
  }

  @Override
  public IMetaschemaData getMetaschemaData() {
    return __metaschemaData;
  }

  public BigInteger getIndex() {
    return _index;
  }

  public void setIndex(BigInteger value) {
    _index = value;
  }

  public String getName() {
    return _name;
  }

  public void setName(String value) {
    _name = value;
  }

  @Override
  public String toString() {
    return new ReflectionToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE).toString();
  }
}
