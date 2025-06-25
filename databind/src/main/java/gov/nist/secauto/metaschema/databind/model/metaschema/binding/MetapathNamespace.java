/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.binding;

import gov.nist.secauto.metaschema.core.datatype.adapter.TokenAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.UriAdapter;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.model.IMetaschemaData;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.MetaschemaAssembly;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.net.URI;

/**
 * Assigns a Metapath namespace to a prefix for use in a Metapath expression in
 * a lexical qualified name.
 */
@SuppressWarnings({
    "PMD.FieldNamingConventions",
})
@MetaschemaAssembly(
    formalName = "Metapath Namespace Declaration",
    description = "Assigns a Metapath namespace to a prefix for use in a Metapath expression in a lexical qualified name.",
    name = "metapath-namespace",
    moduleClass = MetaschemaModelModule.class)
public class MetapathNamespace implements IBoundObject {
  private final IMetaschemaData __metaschemaData;

  /**
   * "The namespace URI to bind to the prefix."
   */
  @BoundFlag(
      formalName = "Metapath Namespace URI",
      description = "The namespace URI to bind to the prefix.",
      name = "uri",
      required = true,
      typeAdapter = UriAdapter.class)
  private URI _uri;

  /**
   * "The prefix that is bound to the namespace."
   */
  @BoundFlag(
      formalName = "Metapath Namespace Prefix",
      description = "The prefix that is bound to the namespace.",
      name = "prefix",
      required = true,
      typeAdapter = TokenAdapter.class)
  private String _prefix;

  public MetapathNamespace() {
    this(null);
  }

  public MetapathNamespace(IMetaschemaData data) {
    this.__metaschemaData = data;
  }

  @Override
  public IMetaschemaData getMetaschemaData() {
    return __metaschemaData;
  }

  public URI getUri() {
    return _uri;
  }

  public void setUri(URI value) {
    _uri = value;
  }

  public String getPrefix() {
    return _prefix;
  }

  public void setPrefix(String value) {
    _prefix = value;
  }

  @Override
  public String toString() {
    return new ReflectionToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE).toString();
  }
}
