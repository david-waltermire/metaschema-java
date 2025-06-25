/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.AbstractInlineAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerFlagSupport;
import gov.nist.secauto.metaschema.core.model.IContainerModelAbsolute;
import gov.nist.secauto.metaschema.core.model.IContainerModelAssemblySupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IModelElementVisitor;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.AssemblyConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IModelConstrained;
import gov.nist.secauto.metaschema.core.model.xml.XmlModuleConstants;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.impl.IFeatureInstanceModelGroupAs;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingInstance;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.AssemblyConstraints;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.JsonKey;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public class InstanceModelAssemblyInline
    extends AbstractInlineAssemblyDefinition<
        IContainerModelAbsolute,
        IAssemblyDefinition,
        IAssemblyInstanceAbsolute,
        IBindingDefinitionModelAssembly,
        IFlagInstance,
        IModelInstanceAbsolute,
        INamedModelInstanceAbsolute,
        IFieldInstanceAbsolute,
        IAssemblyInstanceAbsolute,
        IChoiceInstance,
        IChoiceGroupInstance>
    implements IAssemblyInstanceAbsolute, IBindingInstance, IBindingDefinitionModelAssembly,
    IFeatureInstanceModelGroupAs {
  @NonNull
  private final InlineDefineAssembly binding;
  @NonNull
  private final Map<IAttributable.Key, Set<String>> properties;
  @NonNull
  private final IGroupAs groupAs;
  @NonNull
  private final Lazy<IAssemblyNodeItem> boundNodeItem;
  @NonNull
  private final Lazy<IContainerFlagSupport<IFlagInstance>> flagContainer;
  @NonNull
  private final Lazy<IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance>> modelContainer;
  @NonNull
  private final Lazy<IModelConstrained> modelConstraints;

  /**
   * Construct a new assembly instance that defines the assembly inline.
   *
   * @param binding
   *          the assembly reference instance object bound to a Java class
   * @param bindingInstance
   *          the Metaschema module instance for the bound object
   * @param position
   *          the zero-based position of this bound object relative to its bound
   *          object siblings
   * @param parent
   *          the assembly definition containing this binding
   * @param nodeItemFactory
   *          the node item factory used to generate child nodes
   */
  public InstanceModelAssemblyInline(
      @NonNull InlineDefineAssembly binding,
      @NonNull IBoundInstanceModelGroupedAssembly bindingInstance,
      int position,
      @NonNull IContainerModelAbsolute parent,
      @NonNull INodeItemFactory nodeItemFactory) {
    super(parent);
    this.binding = binding;
    this.properties = ModelSupport.parseProperties(ObjectUtils.requireNonNull(binding.getProps()));
    this.groupAs = ModelSupport.groupAs(binding.getGroupAs(), parent.getOwningDefinition().getContainingModule());
    this.boundNodeItem = ObjectUtils.notNull(
        Lazy.of(() -> (IAssemblyNodeItem) ObjectUtils.notNull(getContainingDefinition().getSourceNodeItem())
            .getModelItemsByName(bindingInstance.getQName())
            .get(position)));
    this.flagContainer = ObjectUtils.notNull(Lazy.of(() -> {
      JsonKey jsonKey = getBinding().getJsonKey();
      return FlagContainerSupport.newFlagContainer(
          binding.getFlags(),
          bindingInstance,
          this,
          jsonKey == null ? null : jsonKey.getFlagRef());
    }));
    this.modelContainer = ObjectUtils.notNull(Lazy.of(() -> AssemblyModelGenerator.of(
        binding.getModel(),
        ObjectUtils.requireNonNull(bindingInstance.getDefinition()
            .getAssemblyInstanceByName(XmlModuleConstants.MODEL_QNAME.getIndexPosition())),
        this,
        nodeItemFactory)));

    ISource source = parent.getOwningDefinition().getContainingModule().getSource();

    this.modelConstraints = ObjectUtils.notNull(Lazy.of(() -> {
      IModelConstrained retval = new AssemblyConstraintSet(source);
      AssemblyConstraints constraints = getBinding().getConstraint();
      if (constraints != null) {
        ConstraintBindingSupport.parse(
            retval,
            constraints,
            source);
      }
      return retval;
    }));
  }

  @NonNull
  protected InlineDefineAssembly getBinding() {
    getContainingDefinition();
    return binding;
  }

  @Override
  public IBindingMetaschemaModule getContainingModule() {
    return getContainingDefinition().getContainingModule();
  }

  @Override
  public Map<IAttributable.Key, Set<String>> getProperties() {
    return properties;
  }

  @Override
  public IGroupAs getGroupAs() {
    return groupAs;
  }

  @Override
  public IAssemblyNodeItem getSourceNodeItem() {
    return ObjectUtils.notNull(boundNodeItem.get());
  }

  @Override
  public IContainerFlagSupport<IFlagInstance> getFlagContainer() {
    return ObjectUtils.notNull(flagContainer.get());
  }

  @Override
  public IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance> getModelContainer() {
    return ObjectUtils.notNull(modelContainer.get());
  }

  @Override
  public IModelConstrained getConstraintSupport() {
    return ObjectUtils.notNull(modelConstraints.get());
  }

  @Override
  public <CONTEXT, RESULT> RESULT accept(IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return IAssemblyInstanceAbsolute.super.accept(visitor, context);
  }

  // ---------------------------------------
  // - Start binding driven code - CPD-OFF -
  // ---------------------------------------

  @Override
  public String getName() {
    return ObjectUtils.notNull(getBinding().getName());
  }

  @Override
  public Integer getIndex() {
    return ModelSupport.index(getBinding().getIndex());
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
  public MarkupMultiline getRemarks() {
    return ModelSupport.remarks(getBinding().getRemarks());
  }

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
}
