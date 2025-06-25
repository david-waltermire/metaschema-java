/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IModuleNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.model.IDefinition;
import gov.nist.secauto.metaschema.core.model.IModelElementVisitor;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A set of constraints, which are targeted at the contents of a Metaschema
 * module within specific contexts.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public class MetaConstraintSet
    extends AbstractConstraintSet {
  private static final Logger LOGGER = LogManager.getLogger(MetaConstraintSet.class);
  @NonNull
  private final List<? extends IConstraintSet> imports;
  @NonNull
  private final List<Context> contexts;

  /**
   * Construct a new constraint set.
   *
   * @param source
   *          the source of the constraint set
   * @param imports
   *          other constraint sets imported by this set
   * @param contexts
   *          the contexts to use for this constraint set
   */
  public MetaConstraintSet(
      @NonNull ISource source,
      @NonNull List<? extends IConstraintSet> imports,
      @NonNull List<Context> contexts) {
    super(source);
    this.imports = imports;
    this.contexts = contexts;
  }

  @Override
  public Collection<? extends IConstraintSet> getImportedConstraintSets() {
    return imports;
  }

  @Override
  public void applyConstraintsForModule(
      IModuleNodeItem moduleItem,
      IModelElementVisitor<ITargetedConstraints, Void> visitor) {

    for (IConstraintSet imported : imports) {
      imported.applyConstraintsForModule(moduleItem, visitor);
    }

    IModule module = moduleItem.getModule();
    if (LOGGER.isDebugEnabled()) {
      LOGGER.atDebug().log("Applying '{}' constraints to '{}' module.",
          getSource().getLocationHint(),
          module.getLocationHint());
    }

    // generate a dynamic context using the external constraint set's static context
    DynamicContext dynamicContext = new DynamicContext(getSource().getStaticContext());
    for (Context context : contexts) {
      context.applyConstraintsForModule(
          moduleItem,
          dynamicContext,
          visitor,
          ISequence.of(moduleItem));
    }
  }

  /**
   * A nestable context, targeted by a set of metapath expressions, to apply
   * constraints within.
   */
  public static class Context {
    @NonNull
    private final List<IMetapathExpression> metapaths;
    @NonNull
    private final Lazy<List<IMetapathExpression>> contextualizedMetapaths;
    @NonNull
    private final List<Context> childContexts = new LinkedList<>();
    @NonNull
    private final Lazy<ITargetedConstraints> constraints;
    @NonNull
    private final Set<IDefinition> previouslyTargetedDefinitions = new HashSet<>();

    /**
     * Construct a new context.
     *
     * @param parent
     *          the parent content or {@code null} if there is no parent
     * @param source
     *          the source of the constraint set
     * @param metapaths
     *          the metapath expressions the context applies to
     * @param modelConstrained
     *          the constraints to apply to items matching one of the metapaths
     */
    public Context(
        @Nullable Context parent,
        @NonNull ISource source,
        @NonNull List<IMetapathExpression> metapaths,
        @NonNull IModelConstrained modelConstrained) {
      this.metapaths = metapaths;
      this.contextualizedMetapaths
          = ObjectUtils.notNull(Lazy.of(() -> concatMetapaths(parent, ObjectUtils.notNull(metapaths.stream()), source)
              .collect(Collectors.toUnmodifiableList())));

      this.constraints = ObjectUtils.notNull(Lazy.of(() -> new ModelTargetedConstraints(
          source,
          this::getContextualizedMetapaths,
          modelConstrained)));
    }

    /**
     * Get the set of constraints associated with this context.
     *
     * @return the set of constraints
     */
    @NonNull
    private ITargetedConstraints getConstraints() {
      return ObjectUtils.notNull(constraints.get());
    }

    /**
     * Add a collection of child contexts to this context.
     *
     * @param children
     *          the children context to add
     */
    public void addAll(@NonNull Collection<Context> children) {
      childContexts.addAll(children);
    }

    @NonNull
    private List<IMetapathExpression> getMetapaths() {
      return metapaths;
    }

    @NonNull
    private List<IMetapathExpression> getContextualizedMetapaths() {
      return ObjectUtils.notNull(contextualizedMetapaths.get());
    }

    void applyConstraintsForModule(
        @NonNull IModuleNodeItem moduleItem,
        @NonNull DynamicContext dynamicContext,
        @NonNull IModelElementVisitor<ITargetedConstraints, Void> visitor,
        @NonNull ISequence<? extends INodeItem> contextItems) {
      ISequence<? extends IDefinitionNodeItem<?, ?>> targetedItems = ISequence.of(ObjectUtils.notNull(
          contextItems.stream()
              .flatMap(item -> getMetapaths().stream()
                  .flatMap(metapath -> metapath.evaluate(item, dynamicContext).stream()
                      .filter(result -> filterNonDefinitionItem(result, metapath))
                      .map(result -> (IDefinitionNodeItem<?, ?>) result)))))
          .reusable();

      // process this context
      Set<IDefinition> definitions = targetedItems.stream()
          .map(IDefinitionNodeItem::getDefinition)
          // ensure the definition only gets processed if the module being processed is
          // the containing module
          .filter(definition -> !previouslyTargetedDefinitions.contains(definition))
          .collect(Collectors.toUnmodifiableSet());

      // apply the constraints for this context
      definitions.forEach(definition -> {
        definition.accept(visitor, getConstraints());
      });
      previouslyTargetedDefinitions.addAll(definitions);

      // process child contexts, which will be applied depth first
      for (Context childContext : childContexts) {
        childContext.applyConstraintsForModule(
            moduleItem,
            dynamicContext,
            visitor,
            targetedItems);
      }
    }

    @NonNull
    private static Stream<IMetapathExpression> concatMetapaths(
        @Nullable MetaConstraintSet.Context parent,
        @NonNull Stream<IMetapathExpression> metapaths,
        @NonNull ISource source) {

      Stream<IMetapathExpression> retval = metapaths;
      if (parent != null) {
        List<IMetapathExpression> parentMetapaths = parent.getMetapaths().stream()
            .collect(Collectors.toList());
        retval = metapaths
            .map(IMetapathExpression::getPath)
            .flatMap(childPath -> parentMetapaths.stream()
                .map(parentPath -> parentPath.getPath() + '/' + childPath))
            .map(metapath -> IMetapathExpression.lazyCompile(
                ObjectUtils.requireNonNull(metapath),
                source.getStaticContext()));
      }
      return ObjectUtils.notNull(retval);
    }

    private static boolean filterNonDefinitionItem(IItem item, @NonNull IMetapathExpression metapath) {
      boolean retval = item instanceof IDefinitionNodeItem;
      if (!retval) {
        LOGGER.atError().log(
            "Found non-definition item '{}' while applying external constraints using target expression '{}'.",
            item.toString(),
            metapath.getPath());
      }
      return retval;
    }
  }
}
