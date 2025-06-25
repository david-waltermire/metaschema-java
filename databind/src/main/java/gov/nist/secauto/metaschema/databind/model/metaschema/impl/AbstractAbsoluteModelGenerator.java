/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.DefaultChoiceModelBuilder;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IContainerModelAbsolute;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.util.ModuleUtils;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModelGroupedAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.AssemblyReference;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.FieldReference;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineAssembly;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.InlineDefineField;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Supports generating the model contents of a Metaschema instance with a
 * complex structure.
 * <p>
 * This class is not thread safe.
 *
 * @param <PARENT>
 *          the Java type of the parent Metaschema object that contains the
 *          generated model
 * @param <BUILDER>
 *          the Java type of the builder to use to gather the container
 *          instances
 */
@SuppressWarnings({
    "PMD.AbstractClassWithoutAbstractMethod",
})
public abstract class AbstractAbsoluteModelGenerator<
    PARENT extends IContainerModelAbsolute,
    BUILDER extends DefaultChoiceModelBuilder<
        IModelInstanceAbsolute,
        INamedModelInstanceAbsolute,
        IFieldInstanceAbsolute,
        IAssemblyInstanceAbsolute>> {
  @NonNull
  private final PARENT parent;
  @NonNull
  private final INodeItemFactory nodeItemFactory;
  @NonNull
  private final BUILDER builder;

  // counters to track child positions
  private int assemblyReferencePosition; // 0
  private int assemblyInlineDefinitionPosition; // 0
  private int fieldReferencePosition; // 0
  private int fieldInlineDefinitionPosition; // 0

  /**
   * Construct a new generator.
   *
   * @param parent
   *          the parent that owns this container
   * @param nodeItemFactory
   *          the factory used to create new nodes within this container
   * @param builder
   *          the builder to use to gather the container instances
   */
  protected AbstractAbsoluteModelGenerator(
      @NonNull PARENT parent,
      @NonNull INodeItemFactory nodeItemFactory,
      @NonNull BUILDER builder) {
    this.parent = parent;
    this.nodeItemFactory = nodeItemFactory;
    this.builder = builder;
  }

  /**
   * Get the parent that owns this container.
   *
   * @return the parent
   */
  @NonNull
  protected PARENT getParent() {
    return parent;
  }

  /**
   * Get the factory used to create new nodes within this container.
   *
   * @return the factory
   */
  @NonNull
  protected INodeItemFactory getNodeItemFactory() {
    return nodeItemFactory;
  }

  /**
   * Get the builder to use to gather the container instances.
   *
   * @return the builder
   */
  protected BUILDER getBuilder() {
    return builder;
  }

  /**
   * Add an assembly instance to the builder that is generated from the provided
   * arguments.
   *
   * @param obj
   *          a bound assembly reference
   * @param objInstance
   *          the Metaschema instance for the bound object
   */
  protected void addAssemblyInstance(
      @NonNull AssemblyReference obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    IAssemblyDefinition owningDefinition = getParent().getOwningDefinition();
    IModule module = owningDefinition.getContainingModule();

    String name = ObjectUtils.requireNonNull(obj.getRef());
    IAssemblyDefinition definition = module.getScopedAssemblyDefinitionByName(
        ModuleUtils.parseModelName(module, name).getIndexPosition());

    if (definition == null) {
      throw new IllegalStateException(
          String.format("Unable to resolve assembly reference '%s' in definition '%s' in module '%s'",
              name,
              owningDefinition.getName(),
              module.getShortName()));
    }
    getBuilder().append(new InstanceModelAssemblyReference(
        obj,
        objInstance,
        assemblyReferencePosition++,
        definition,
        getParent()));
  }

  /**
   * Add an assembly instance to the builder that is generated from the provided
   * arguments.
   *
   * @param obj
   *          a bound inline assembly
   * @param objInstance
   *          the Metaschema instance for the bound object
   */
  protected void addAssemblyInstance(
      @NonNull InlineDefineAssembly obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    getBuilder().append(new InstanceModelAssemblyInline(
        obj,
        objInstance,
        assemblyInlineDefinitionPosition++,
        getParent(),
        getNodeItemFactory()));
  }

  /**
   * Add a field instance to the builder that is generated from the provided
   * arguments.
   *
   * @param obj
   *          a bound field reference
   * @param objInstance
   *          the Metaschema instance for the bound object
   */
  protected void addFieldInstance(
      @NonNull FieldReference obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    IAssemblyDefinition owningDefinition = getParent().getOwningDefinition();
    IModule module = owningDefinition.getContainingModule();

    String name = ObjectUtils.requireNonNull(obj.getRef());
    IFieldDefinition definition = module.getScopedFieldDefinitionByName(
        ModuleUtils.parseModelName(module, name).getIndexPosition());
    if (definition == null) {
      throw new IllegalStateException(
          String.format("Unable to resolve field reference '%s' in definition '%s' in module '%s'",
              name,
              owningDefinition.getName(),
              module.getShortName()));
    }
    getBuilder().append(new InstanceModelFieldReference(
        obj,
        objInstance,
        fieldReferencePosition++,
        definition,
        getParent()));
  }

  /**
   * Add a field instance to the builder that is generated from the provided
   * arguments.
   *
   * @param obj
   *          a bound inline field
   * @param objInstance
   *          the Metaschema instance for the bound object
   */

  protected void addFieldInstance(
      @NonNull InlineDefineField obj,
      @NonNull IBoundInstanceModelGroupedAssembly objInstance) {
    getBuilder().append(new InstanceModelFieldInline(
        obj,
        objInstance,
        fieldInlineDefinitionPosition++,
        getParent()));
  }

  @SuppressWarnings({ "PMD.EmptyFinalizer", "checkstyle:NoFinalizer" })
  @SuppressFBWarnings(value = "FI_EMPTY", justification = "needed to avoid finalization bug")
  @Override
  protected final void finalize() {
    // Address SEI CERT Rule OBJ-11:
    // https://wiki.sei.cmu.edu/confluence/display/java/OBJ11-J.+Be+wary+of+letting+constructors+throw+exceptions
  }
}
