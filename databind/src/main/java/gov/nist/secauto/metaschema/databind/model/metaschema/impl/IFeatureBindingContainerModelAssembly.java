/*
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.model.IContainerModelAssemblySupport;
import gov.nist.secauto.metaschema.core.model.IFeatureContainerModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingContainerModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstanceModelAbsolute;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstanceModelAssemblyAbsolute;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstanceModelFieldAbsolute;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstanceModelNamedAbsolute;
import gov.nist.secauto.metaschema.databind.model.metaschema.IInstanceModelChoiceBinding;
import gov.nist.secauto.metaschema.databind.model.metaschema.IInstanceModelChoiceGroupBinding;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IFeatureBindingContainerModelAssembly
    extends IBindingContainerModelAssembly,
    IFeatureBindingContainerModel,
    IFeatureContainerModelAssembly<
        IBindingInstanceModelAbsolute,
        IBindingInstanceModelNamedAbsolute,
        IBindingInstanceModelFieldAbsolute,
        IBindingInstanceModelAssemblyAbsolute,
        IInstanceModelChoiceBinding,
        IInstanceModelChoiceGroupBinding> {
  @Override
  @NonNull
  IContainerModelAssemblySupport<
      IBindingInstanceModelAbsolute,
      IBindingInstanceModelNamedAbsolute,
      IBindingInstanceModelFieldAbsolute,
      IBindingInstanceModelAssemblyAbsolute,
      IInstanceModelChoiceBinding,
      IInstanceModelChoiceGroupBinding> getModelContainer();

  @Override
  default Collection<IBindingInstanceModelAbsolute> getModelInstances() {
    return getModelContainer().getModelInstances();
  }

  @Override
  default IBindingInstanceModelNamedAbsolute getNamedModelInstanceByName(String name) {
    return getModelContainer().getNamedModelInstanceMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  default Collection<IBindingInstanceModelNamedAbsolute> getNamedModelInstances() {
    return getModelContainer().getNamedModelInstanceMap().values();
  }

  @Override
  default IBindingInstanceModelFieldAbsolute getFieldInstanceByName(String name) {
    return getModelContainer().getFieldInstanceMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  default Collection<IBindingInstanceModelFieldAbsolute> getFieldInstances() {
    return getModelContainer().getFieldInstanceMap().values();
  }

  @Override
  default IBindingInstanceModelAssemblyAbsolute getAssemblyInstanceByName(String name) {
    return getModelContainer().getAssemblyInstanceMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  default Collection<IBindingInstanceModelAssemblyAbsolute> getAssemblyInstances() {
    return getModelContainer().getAssemblyInstanceMap().values();
  }

  @Override
  default List<IInstanceModelChoiceBinding> getChoiceInstances() {
    return getModelContainer().getChoiceInstances();
  }

  @Override
  default IInstanceModelChoiceGroupBinding getChoiceGroupInstanceByName(String name) {
    return getModelContainer().getChoiceGroupInstanceMap().get(name);
  }

  @Override
  default Map<String, IInstanceModelChoiceGroupBinding> getChoiceGroupInstances() {
    return getModelContainer().getChoiceGroupInstanceMap();
  }
}
