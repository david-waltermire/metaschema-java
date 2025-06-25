/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.AbstractChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IContainerModelSupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstance;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.AssemblyModel;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public class InstanceModelChoice
    extends AbstractChoiceInstance<
        IBindingDefinitionModelAssembly,
        IModelInstanceAbsolute,
        INamedModelInstanceAbsolute,
        IFieldInstanceAbsolute,
        IAssemblyInstanceAbsolute>
    implements IBindingInstance {
  @NonNull
  private final Lazy<IContainerModelSupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute>> modelContainer;
  @NonNull
  private final Lazy<IAssemblyNodeItem> boundNodeItem;

  public InstanceModelChoice(
      @NonNull AssemblyModel.Choice binding,
      @NonNull IBoundInstanceModelGroupedAssembly bindingInstance,
      int position,
      @NonNull IBindingDefinitionModelAssembly parent,
      @NonNull INodeItemFactory nodeItemFactory) {
    super(parent);
    this.modelContainer = ObjectUtils.notNull(Lazy.of(() -> ChoiceModelGenerator.of(
        binding,
        bindingInstance,
        this,
        nodeItemFactory)));
    this.boundNodeItem = ObjectUtils.notNull(
        Lazy.of(() -> (IAssemblyNodeItem) ObjectUtils.notNull(getContainingDefinition().getSourceNodeItem())
            .getModelItemsByName(bindingInstance.getQName())
            .get(position)));
  }

  @Override
  public IBindingMetaschemaModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  @Override
  public IContainerModelSupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute> getModelContainer() {
    return ObjectUtils.notNull(modelContainer.get());
  }

  @Override
  public IAssemblyNodeItem getSourceNodeItem() {
    return ObjectUtils.notNull(boundNodeItem.get());
  }

  @Override
  public IAssemblyDefinition getOwningDefinition() {
    return getContainingDefinition();
  }

  @Override
  public MarkupMultiline getRemarks() {
    // no remarks
    return null;
  }

}
