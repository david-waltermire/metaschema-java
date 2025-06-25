/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.model.AbstractInlineFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IFeatureValueless;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingDefinitionModel;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstance;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.FlagConstraints;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineFlag;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

public class InstanceFlagInline
    extends AbstractInlineFlagDefinition<
        IBindingDefinitionModel,
        IFlagDefinition,
        IFlagInstance>
    implements IFeatureValueless, IBindingInstance {
  @NonNull
  private final InlineDefineFlag binding;
  @NonNull
  private final Map<IAttributable.Key, Set<String>> properties;
  @NonNull
  private final IDataTypeAdapter<?> javaTypeAdapter;
  @Nullable
  private final Object defaultValue;
  @NonNull
  private final Lazy<IValueConstrained> valueConstraints;
  @NonNull
  private final Lazy<IAssemblyNodeItem> boundNodeItem;

  public InstanceFlagInline(
      @NonNull InlineDefineFlag binding,
      @NonNull IBoundInstanceModelGroupedAssembly bindingInstance,
      int position,
      @NonNull IBindingDefinitionModel parent) {
    super(parent);
    this.binding = binding;
    this.properties = ModelSupport.parseProperties(ObjectUtils.requireNonNull(binding.getProps()));

    ISource source = parent.getContainingModule().getSource();

    this.javaTypeAdapter = ModelSupport.dataType(
        binding.getAsType(),
        source);
    this.defaultValue = ModelSupport.defaultValue(binding.getDefault(), this.javaTypeAdapter);
    this.valueConstraints = ObjectUtils.notNull(Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      FlagConstraints constraints = binding.getConstraint();
      if (constraints != null) {
        ConstraintBindingSupport.parse(retval, constraints, source);
      }
      return retval;
    }));
    this.boundNodeItem = ObjectUtils.notNull(
        Lazy.of(() -> (IAssemblyNodeItem) ObjectUtils.notNull(parent.getSourceNodeItem())
            .getModelItemsByName(bindingInstance.getQName())
            .get(position)));
  }

  @NonNull
  protected InlineDefineFlag getBinding() {
    return binding;
  }

  @Override
  public IBindingMetaschemaModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  @SuppressWarnings("null")
  @Override
  public IValueConstrained getConstraintSupport() {
    return valueConstraints.get();
  }

  @Override
  public IAssemblyNodeItem getSourceNodeItem() {
    return ObjectUtils.notNull(boundNodeItem.get());
  }

  @Override
  public Map<IAttributable.Key, Set<String>> getProperties() {
    return properties;
  }

  @Override
  public IDataTypeAdapter<?> getJavaTypeAdapter() {
    return javaTypeAdapter;
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue;
  }

  @Override
  public String getName() {
    return ObjectUtils.notNull(getBinding().getName());
  }

  @Override
  public String getFormalName() {
    return getBinding().getFormalName();
  }

  @Override
  public MarkupLine getDescription() {
    return getBinding().getDescription();
  }

  @Override
  public Integer getIndex() {
    return ModelSupport.index(getBinding().getIndex());
  }

  @Override
  public MarkupMultiline getRemarks() {
    return ModelSupport.remarks(getBinding().getRemarks());
  }

  @Override
  public boolean isRequired() {
    return ModelSupport.yesOrNo(getBinding().getRequired());
  }

  // =================================
  // IAssemnblyNodeItem implementation
  // =================================
}
