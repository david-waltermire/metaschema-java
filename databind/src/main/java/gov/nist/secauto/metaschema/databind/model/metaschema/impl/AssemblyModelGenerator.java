/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.DefaultAssemblyModelBuilder;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelAssemblySupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelChoiceGroup;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.AssemblyModel;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.AssemblyReference;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.FieldReference;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineField;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Supports building the model contents of a Metaschema assembly definition.
 * <p>
 * This class is not thread safe.
 */
public final class AssemblyModelGenerator
    extends AbstractAbsoluteModelGenerator<
        IBindingDefinitionModelAssembly,
        DefaultAssemblyModelBuilder<
            IModelInstanceAbsolute,
            INamedModelInstanceAbsolute,
            IFieldInstanceAbsolute,
            IAssemblyInstanceAbsolute,
            IChoiceInstance,
            IChoiceGroupInstance>> {
  // counters to track child positions
  private int choicePosition; // 0
  private int choiceGroupPosition; // 0

  /**
   * Construct a new choice model container.
   *
   * @param binding
   *          the choice model object bound to a Java class
   * @param bindingInstance
   *          the Metaschema module instance for the bound model object
   * @param parent
   *          the assembly definition containing this container
   * @param nodeItemFactory
   *          the node item factory used to generate child nodes
   * @return the container
   */
  @SuppressWarnings("PMD.ShortMethodName")
  public static IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance> of(
          @Nullable AssemblyModel binding,
          @NonNull IBoundInstanceModelAssembly bindingInstance,
          @NonNull IBindingDefinitionModelAssembly parent,
          @NonNull INodeItemFactory nodeItemFactory) {
    List<Object> instances;
    return binding == null || (instances = binding.getInstances()) == null || instances.isEmpty()
        ? IContainerModelAssemblySupport.empty()
        : newInstance(
            binding,
            bindingInstance,
            parent,
            nodeItemFactory);
  }

  private static IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance> newInstance(
          @NonNull AssemblyModel binding,
          @NonNull IBoundInstanceModelAssembly bindingInstance,
          @NonNull IBindingDefinitionModelAssembly parent,
          @NonNull INodeItemFactory nodeItemFactory) {
    AssemblyModelGenerator generator = new AssemblyModelGenerator(parent, nodeItemFactory);

    // TODO: make "instances" a constant
    IBoundInstanceModelChoiceGroup instance = ObjectUtils.requireNonNull(
        bindingInstance.getDefinition()
            .getChoiceGroupInstanceByName(BindingConstants.METASCHEMA_CHOICE_GROUP_GROUP_AS_NAME));

    ObjectUtils.notNull(binding.getInstances()).forEach(obj -> {
      assert obj != null;
      IBoundInstanceModelGroupedAssembly objInstance
          = (IBoundInstanceModelGroupedAssembly) instance.getItemInstance(obj);

      if (obj instanceof AssemblyReference) {
        generator.addAssemblyInstance((AssemblyReference) obj, objInstance);
      } else if (obj instanceof InlineDefineAssembly) {
        generator.addAssemblyInstance((InlineDefineAssembly) obj, objInstance);
      } else if (obj instanceof FieldReference) {
        generator.addFieldInstance((FieldReference) obj, objInstance);
      } else if (obj instanceof InlineDefineField) {
        generator.addFieldInstance((InlineDefineField) obj, objInstance);
      } else if (obj instanceof AssemblyModel.Choice) {
        generator.addChoiceInstance((AssemblyModel.Choice) obj, objInstance);
      } else if (obj instanceof AssemblyModel.ChoiceGroup) {
        generator.addChoiceGroupInstance((AssemblyModel.ChoiceGroup) obj, objInstance);
      } else {
        throw new UnsupportedOperationException(String.format("Unknown model instance class: %s", obj.getClass()));
      }
    });

    return generator.getBuilder().buildAssembly();
  }

  private AssemblyModelGenerator(
      @NonNull IBindingDefinitionModelAssembly parent,
      @NonNull INodeItemFactory nodeItemFactory) {
    super(parent, nodeItemFactory, new DefaultAssemblyModelBuilder<>());
  }

  private void addChoiceInstance(
      @NonNull AssemblyModel.Choice obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    getBuilder().append(new InstanceModelChoice(
        obj,
        objInstance,
        choicePosition++,
        getParent(),
        getNodeItemFactory()));
  }

  private void addChoiceGroupInstance(
      @NonNull AssemblyModel.ChoiceGroup obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    getBuilder().append(new InstanceModelChoiceGroup(
        obj,
        objInstance,
        choiceGroupPosition++,
        getParent(),
        getNodeItemFactory()));
  }
}
