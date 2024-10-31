/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.AbstractChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.IContainerModelSupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceGrouped;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.binding.metaschema.AssemblyModel;
import gov.nist.secauto.metaschema.databind.model.binding.metaschema.JsonKey;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstance;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;

import java.math.BigInteger;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public class InstanceModelChoiceGroup
    extends AbstractChoiceGroupInstance<
        IBindingDefinitionModelAssembly,
        INamedModelInstanceGrouped,
        IFieldInstanceGrouped,
        IAssemblyInstanceGrouped>
    implements IFeatureInstanceModelGroupAs, IBindingInstance {
  @NonNull
  private final AssemblyModel.ChoiceGroup binding;
  @NonNull
  private final IGroupAs groupAs;
  @NonNull
  private final Lazy<IContainerModelSupport<
      INamedModelInstanceGrouped,
      INamedModelInstanceGrouped,
      IFieldInstanceGrouped,
      IAssemblyInstanceGrouped>> modelContainer;
  @NonNull
  private final Lazy<IAssemblyNodeItem> boundNodeItem;

  public InstanceModelChoiceGroup(
      @NonNull AssemblyModel.ChoiceGroup binding,
      @NonNull IBoundInstanceModelGroupedAssembly bindingInstance,
      int position,
      @NonNull IBindingDefinitionModelAssembly parent,
      @NonNull INodeItemFactory nodeItemFactory) {
    super(parent);
    this.binding = binding;
    this.groupAs = ModelSupport.groupAs(binding.getGroupAs(), parent.getContainingModule());
    this.modelContainer = ObjectUtils.notNull(Lazy.lazy(() -> ChoiceGroupModelContainerSupport.of(
        binding,
        bindingInstance,
        this,
        nodeItemFactory)));
    this.boundNodeItem = ObjectUtils.notNull(
        Lazy.lazy(() -> (IAssemblyNodeItem) ObjectUtils.notNull(getContainingDefinition().getSourceNodeItem())
            .getModelItemsByName(bindingInstance.getXmlQName())
            .get(position)));
  }

  @NonNull
  private AssemblyModel.ChoiceGroup getBinding() {
    return binding;
  }

  @Override
  public IBindingMetaschemaModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  @Override
  public IContainerModelSupport<
      INamedModelInstanceGrouped,
      INamedModelInstanceGrouped,
      IFieldInstanceGrouped,
      IAssemblyInstanceGrouped> getModelContainer() {
    return ObjectUtils.notNull(modelContainer.get());
  }

  @Override
  public IGroupAs getGroupAs() {
    return groupAs;
  }

  @Override
  public IAssemblyNodeItem getSourceNodeItem() {
    return ObjectUtils.notNull(boundNodeItem.get());
  }

  // ---------------------------------------
  // - Start binding driven code - CPD-OFF -
  // ---------------------------------------

  @Override
  public int getMinOccurs() {
    BigInteger min = getBinding().getMinOccurs();
    return min == null ? DEFAULT_GROUP_AS_MIN_OCCURS : min.intValueExact();
  }

  @Override
  public int getMaxOccurs() {
    String max = getBinding().getMaxOccurs();
    return max == null ? DEFAULT_GROUP_AS_MAX_OCCURS : ModelSupport.maxOccurs(max);
  }

  @Override
  public IAssemblyDefinition getOwningDefinition() {
    return getParentContainer();
  }

  @Override
  public String getJsonDiscriminatorProperty() {
    String discriminator = getBinding().getDiscriminator();
    return discriminator == null ? DEFAULT_JSON_DISCRIMINATOR_PROPERTY_NAME : discriminator;
  }

  @Override
  public String getJsonKeyFlagInstanceName() {
    JsonKey jsonKey = getBinding().getJsonKey();
    return jsonKey == null ? null : jsonKey.getFlagRef();
  }
}
