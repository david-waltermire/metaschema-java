/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.util;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IModelDefinition;
import gov.nist.secauto.metaschema.core.model.IModelInstance;
import gov.nist.secauto.metaschema.core.model.INamedInstance;
import gov.nist.secauto.metaschema.core.model.INamedModelInstance;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceGrouped;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A basic implementation of a {@link IDiagramNodeVisitor}.
 */
@SuppressWarnings("PMD.DataClass")
public class DefaultDiagramNode implements IDiagramNode {
  @NonNull
  private final IModelDefinition definition;
  @NonNull
  private final String identifier;
  @NonNull
  private final List<IDiagramNode.IAttribute> attributes;
  @NonNull
  private final Lazy<List<IDiagramNode.IEdge>> edges;

  @NonNull
  private static String getParentContext(@NonNull IModelDefinition definition) {
    String retval;
    if (definition.isInline()) {
      INamedInstance instance = definition.getInlineInstance();
      String name = instance.getEffectiveName();
      retval = getParentContext(instance.getContainingDefinition()) + "_" + name;
    } else {
      retval = definition.getName();
    }
    return retval;
  }

  /**
   * Construct a new diagram node.
   *
   * @param definition
   *          the definition to base the node on
   */
  public DefaultDiagramNode(
      @NonNull IModelDefinition definition) {
    this.definition = definition;
    this.identifier = getParentContext(definition);
    this.attributes = ObjectUtils.notNull(Stream.concat(
        definition.getFlagInstances().stream()
            // all flags
            .map(flag -> new Attribute(flag.getEffectiveName(), flag.getDefinition().getJavaTypeAdapter())),
        definition instanceof IAssemblyDefinition
            ? ((IAssemblyDefinition) definition).getFieldInstances().stream()
                // singleton fields with no flags
                .filter(field -> !INamedModelInstance.complexObjectFilter(field))
                .map(field -> new Attribute(field.getEffectiveName(), field.getDefinition().getJavaTypeAdapter()))
            : Stream.empty())
        .collect(Collectors.toUnmodifiableList()));
    this.edges = ObjectUtils.notNull(Lazy.of(() -> definition instanceof IAssemblyDefinition
        ? generateEdges((IAssemblyDefinition) definition)
        : CollectionUtil.emptyList()));
  }

  @NonNull
  private List<IDiagramNode.IEdge> generateEdges(
      @NonNull IAssemblyDefinition definition) {
    return ObjectUtils.notNull(definition.getModelInstances().stream()
        .flatMap(instance -> {
          Stream<AbstractEdge<?>> retval;
          if (instance instanceof IChoiceInstance) {
            IChoiceInstance choice = (IChoiceInstance) instance;
            retval = choice.getNamedModelInstances().stream()
                .filter(INamedModelInstance::complexObjectFilter)
                .map(ci -> new ChoiceEdge(choice, ObjectUtils.requireNonNull(ci)));
          } else if (instance instanceof IChoiceGroupInstance) {
            IChoiceGroupInstance choiceGroup = (IChoiceGroupInstance) instance;
            retval = choiceGroup.getNamedModelInstances().stream()
                .filter(INamedModelInstance::complexObjectFilter)
                .map(cgi -> new ChoiceGroupEdge(choiceGroup, ObjectUtils.requireNonNull(cgi)));
          } else {
            INamedModelInstanceAbsolute modelInstance = (INamedModelInstanceAbsolute) instance;
            retval = INamedModelInstance.complexObjectFilter(modelInstance)
                ? Stream.of(new ModelEdge(ObjectUtils.requireNonNull(modelInstance)))
                : Stream.empty();
          }
          return retval;
        })
        .collect(Collectors.toUnmodifiableList()));
  }

  @Override
  @NonNull
  public IModelDefinition getDefinition() {
    return definition;
  }

  @Override
  @NonNull
  public String getIdentifier() {
    return identifier;
  }

  @Override
  public List<IAttribute> getAttributes() {
    return attributes;
  }

  @Override
  public List<IEdge> getEdges() {
    return ObjectUtils.notNull(edges.get());
  }

  private final class Attribute implements IDiagramNode.IAttribute {
    @NonNull
    private final String name;
    @NonNull
    private final IDataTypeAdapter<?> dataType;

    private Attribute(@NonNull String name, @NonNull IDataTypeAdapter<?> dataType) {
      this.name = name;
      this.dataType = dataType;
    }

    @Override
    public IDiagramNode getNode() {
      return DefaultDiagramNode.this;
    }

    @Override
    @NonNull
    public String getLabel() {
      return name;
    }

    @Override
    @NonNull
    public IDataTypeAdapter<?> getDataType() {
      return dataType;
    }
  }

  private abstract class AbstractEdge<T extends IModelInstance> implements IDiagramNode.IEdge {
    @NonNull
    private final Relationship relationship;
    @NonNull
    private final T instance;

    protected AbstractEdge(
        @NonNull Relationship relationship,
        @NonNull T instance) {
      this.relationship = relationship;
      this.instance = instance;
    }

    @Override
    public IDiagramNode getNode() {
      return DefaultDiagramNode.this;
    }

    @Override
    @NonNull
    public Relationship getRelationship() {
      return relationship;
    }

    @Override
    @NonNull
    public T getInstance() {
      return instance;
    }
  }

  public final class ModelEdge
      extends AbstractEdge<INamedModelInstanceAbsolute> {
    private ModelEdge(
        @NonNull INamedModelInstanceAbsolute instance) {
      super(Relationship.toRelationship(instance), instance);
    }

    @Override
    public void accept(IDiagramNodeVisitor visitor) {
      visitor.visit(this);
    }
  }

  public final class ChoiceEdge
      extends AbstractEdge<INamedModelInstanceAbsolute> {
    @NonNull
    private final IChoiceInstance choice;

    private ChoiceEdge(
        @NonNull IChoiceInstance choice,
        @NonNull INamedModelInstanceAbsolute instance) {
      super(Relationship.toRelationship(instance), instance);
      this.choice = choice;
    }

    /**
     * Get the associated choice.
     *
     * @return the choice instance
     */
    @NonNull
    public IChoiceInstance getChoice() {
      return choice;
    }

    @Override
    public void accept(IDiagramNodeVisitor visitor) {
      visitor.visit(this);
    }
  }

  public final class ChoiceGroupEdge
      extends AbstractEdge<INamedModelInstanceGrouped> {
    @NonNull
    private final IChoiceGroupInstance choiceGroup;

    private ChoiceGroupEdge(
        @NonNull IChoiceGroupInstance choiceGroup,
        @NonNull INamedModelInstanceGrouped instance) {
      super(Relationship.toRelationship(choiceGroup), instance);
      this.choiceGroup = choiceGroup;
    }

    /**
     * Get the associated choice group.
     *
     * @return the choice group instance
     */
    @NonNull
    public IChoiceGroupInstance getChoiceGroup() {
      return choiceGroup;
    }

    @Override
    public void accept(IDiagramNodeVisitor visitor) {
      visitor.visit(this);
    }
  }
}
