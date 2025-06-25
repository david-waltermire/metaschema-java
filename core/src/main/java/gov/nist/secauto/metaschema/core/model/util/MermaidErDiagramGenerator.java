/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.util;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IModelDefinition;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.ModelWalker;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.jdt.annotation.NotOwning;

import java.io.PrintWriter;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Generates a mermaid diagram from a Metaschema {@link IModule}.
 */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.UseConcurrentHashMap" })
public final class MermaidErDiagramGenerator {
  @NonNull
  private static final Lazy<Map<IDiagramNode.Relationship, Pair<String, String>>> RELATIONSHIP_SYMBOLS
      = ObjectUtils.notNull(Lazy.of(() -> {
        Map<IDiagramNode.Relationship, Pair<String, String>> retval = new EnumMap<>(IDiagramNode.Relationship.class);

        retval.put(IDiagramNode.Relationship.ZERO_OR_ONE, Pair.of("|o", "o|"));
        retval.put(IDiagramNode.Relationship.ONE, Pair.of("||", "||"));
        retval.put(IDiagramNode.Relationship.ZERO_OR_MORE, Pair.of("}o", "o{"));
        retval.put(IDiagramNode.Relationship.ONE_OR_MORE, Pair.of("}|", "|{"));

        return CollectionUtil.unmodifiableMap(retval);
      }));

  private static String generateRelationsip(@NonNull IDiagramNode.Relationship relationship) {
    Pair<String, String> symbols = RELATIONSHIP_SYMBOLS.get().get(relationship);
    return symbols.getLeft() + "--" + symbols.getRight();
  }

  /**
   * Generate a Mermaid diagram for the provided module, using the provided
   * writer.
   *
   * @param module
   *          the Metaschema module to create a diagram for
   * @param writer
   *          the writer to use to generate the diagram code
   */
  public static void generate(@NonNull IModule module, @NonNull PrintWriter writer) {
    DiagramNodeModelVisitor visitor = new DiagramNodeModelVisitor();

    writer.println("erDiagram");

    for (IAssemblyDefinition root : module.getExportedRootAssemblyDefinitions()) {
      assert root != null;
      visitor.walk(root);
    }

    MermaidNodeVistor mermaidVisitor = new MermaidNodeVistor(visitor, writer);
    for (IDiagramNode node : visitor.getNodes()) {
      writer.format("  %s[\"%s\"] {%n", node.getIdentifier(), node.getLabel());

      for (IDiagramNode.IAttribute attribute : node.getAttributes()) {
        writer.format("    %s %s%n",
            attribute.getDataType().getPreferredName().getLocalName(),
            attribute.getLabel());
      }
      writer.format("  }%n");
      for (IDiagramNode.IEdge edge : node.getEdges()) {
        writer.flush();
        edge.accept(mermaidVisitor);
      }
    }

    // writer.print(visitor.getDiagram());
  }

  private static final class MermaidNodeVistor implements IDiagramNodeVisitor {
    @NonNull
    private final DiagramNodeModelVisitor nodeVisitor;
    @SuppressWarnings("resource")
    @NonNull
    private final PrintWriter writer;

    private MermaidNodeVistor(
        @NonNull DiagramNodeModelVisitor nodeVisitor,
        @NotOwning @NonNull PrintWriter writer) {
      this.nodeVisitor = nodeVisitor;
      this.writer = writer;
    }

    @NonNull
    public DiagramNodeModelVisitor getNodeVisitor() {
      return nodeVisitor;
    }

    @NonNull
    @NotOwning
    public PrintWriter getWriter() {
      return writer;
    }

    @Override
    public void visit(DefaultDiagramNode.ModelEdge edge) {
      INamedModelInstanceAbsolute instance = edge.getInstance();
      IModelDefinition definition = instance.getDefinition();
      writeRelationship(
          edge.getNode(),
          ObjectUtils.requireNonNull(getNodeVisitor().lookup(definition)),
          edge.getRelationship(),
          instance.getEffectiveName());
    }

    @Override
    public void visit(DefaultDiagramNode.ChoiceEdge edge) {
      INamedModelInstanceAbsolute instance = edge.getInstance();
      IModelDefinition definition = instance.getDefinition();
      writeRelationship(
          edge.getNode(),
          ObjectUtils.requireNonNull(getNodeVisitor().lookup(definition)),
          edge.getRelationship(),
          "Choice: " + instance.getEffectiveName());
    }

    @Override
    public void visit(DefaultDiagramNode.ChoiceGroupEdge edge) {
      INamedModelInstanceGrouped instance = edge.getInstance();
      IModelDefinition definition = instance.getDefinition();
      writeRelationship(
          edge.getNode(),
          ObjectUtils.requireNonNull(getNodeVisitor().lookup(definition)),
          edge.getRelationship(),
          "ChoiceGroup: " + edge.getInstance().getEffectiveDisciminatorValue() + ": " + instance.getEffectiveName());
    }

    private void writeRelationship(
        @NonNull IDiagramNode left,
        @NonNull IDiagramNode right,
        @NonNull IDiagramNode.Relationship relationship,
        @NonNull String label) {
      getWriter().format("  %s %s %s : \"%s\"%n",
          left.getIdentifier(),
          generateRelationsip(relationship),
          right.getIdentifier(),
          label);
    }
  }

  private static final class DiagramNodeModelVisitor
      extends ModelWalker<Void> {
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    @NonNull
    private final Map<IModelDefinition, IDiagramNode> nodeMap = new LinkedHashMap<>();

    public Collection<IDiagramNode> getNodes() {
      return CollectionUtil.unmodifiableCollection(ObjectUtils.notNull(nodeMap.values()));
    }

    @Nullable
    public IDiagramNode lookup(@NonNull IModelDefinition definition) {
      return nodeMap.get(definition);
    }

    @Override
    protected Void getDefaultData() {
      return null;
    }

    @Override
    protected void visit(IFlagDefinition def, Void data) {
      // do nothing
    }

    @Override
    protected boolean visit(IFieldDefinition def, Void data) {
      return !def.getFlagInstances().isEmpty() && handleDefinition(def);
    }

    @Override
    protected boolean visit(IAssemblyDefinition def, Void data) {
      return handleDefinition(def);
    }

    private boolean handleDefinition(@NonNull IModelDefinition definition) {
      boolean exists = nodeMap.containsKey(definition);
      if (!exists) {
        nodeMap.put(definition, new DefaultDiagramNode(definition));
      }
      return !exists;
    }
  }

  private MermaidErDiagramGenerator() {
    // disable construction
  }
}
