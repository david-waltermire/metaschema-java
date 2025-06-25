/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext.IBindingMatcher;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class RootAssemblyBindingMatcher implements IBindingMatcher {
  @NonNull
  private final IBoundDefinitionModelAssembly definition;
  @NonNull
  private final Lazy<QName> rootQName = ObjectUtils.notNull(
      Lazy.of(() -> getDefinition().getRootQName().toQName()));

  public RootAssemblyBindingMatcher(
      @NonNull IBoundDefinitionModelAssembly definition) {
    this.definition = definition;
  }

  protected IBoundDefinitionModelAssembly getDefinition() {
    return definition;
  }

  protected Class<? extends IBoundObject> getClazz() {
    return getDefinition().getBoundClass();
  }

  @NonNull
  protected QName getRootQName() {
    return ObjectUtils.notNull(rootQName.get());
  }

  @SuppressWarnings("null")
  @NonNull
  protected String getRootJsonName() {
    return getDefinition().getRootJsonName();
  }

  @Override
  public Class<? extends IBoundObject> getBoundClassForXmlQName(QName rootQName) {
    return getRootQName().equals(rootQName) ? getClazz() : null;
  }

  @Override
  public Class<? extends IBoundObject> getBoundClassForJsonName(String rootName) {
    return getRootJsonName().equals(rootName) ? getClazz() : null;
  }

  @Override
  public String toString() {
    return getDefinition().getRootQName().toString();
  }
}
