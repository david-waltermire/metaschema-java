/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.function.library.FnBoolean;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.node.AbstractNodeItemVisitor;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFieldNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFlagNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IModuleNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ExceptionUtils;
import gov.nist.secauto.metaschema.core.util.ExceptionUtils.WrappedException;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Used to perform constraint validation over one or more node items.
 * <p>
 * This class is not thread safe.
 */
@SuppressWarnings({
    "PMD.CouplingBetweenObjects",
    "PMD.GodClass" // provides validators for all types
})
public class DefaultConstraintValidator
    implements IConstraintValidator, IMutableConfiguration<ValidationFeature<?>> {
  private static final Logger LOGGER = LogManager.getLogger(DefaultConstraintValidator.class);

  @NonNull
  private final Map<INodeItem, ValueStatus> valueMap = new LinkedHashMap<>(); // NOPMD - intentional
  @NonNull
  private final Map<String, IIndex> indexNameToIndexMap = new ConcurrentHashMap<>();
  @NonNull
  private final Map<String, List<KeyRef>> indexNameToKeyRefMap = new ConcurrentHashMap<>();
  @NonNull
  private final IConstraintValidationHandler handler;
  @NonNull
  private final IMutableConfiguration<ValidationFeature<?>> configuration;

  /**
   * Construct a new constraint validation instance.
   *
   * @param handler
   *          the validation handler to use for handling constraint violations
   */
  public DefaultConstraintValidator(
      @NonNull IConstraintValidationHandler handler) {
    this.handler = handler;
    this.configuration = new DefaultConfiguration<>();
  }

  /**
   * Get the current configuration of the serializer/deserializer.
   *
   * @return the configuration
   */
  @NonNull
  protected IMutableConfiguration<ValidationFeature<?>> getConfiguration() {
    return configuration;
  }

  @Override
  public DefaultConstraintValidator enableFeature(ValidationFeature<?> feature) {
    return set(feature, true);
  }

  @Override
  public DefaultConstraintValidator disableFeature(ValidationFeature<?> feature) {
    return set(feature, false);
  }

  @Override
  public DefaultConstraintValidator applyConfiguration(
      @NonNull IConfiguration<ValidationFeature<?>> other) {
    getConfiguration().applyConfiguration(other);
    return this;
  }

  @Override
  public DefaultConstraintValidator set(ValidationFeature<?> feature, Object value) {
    getConfiguration().set(feature, value);
    return this;
  }

  @Override
  public boolean isFeatureEnabled(ValidationFeature<?> feature) {
    return getConfiguration().isFeatureEnabled(feature);
  }

  @Override
  public Map<ValidationFeature<?>, Object> getFeatureValues() {
    return getConfiguration().getFeatureValues();
  }

  /**
   * Get the validation handler to use for handling constraint violations.
   *
   * @return the handler
   */
  @NonNull
  protected IConstraintValidationHandler getConstraintValidationHandler() {
    return handler;
  }

  @Override
  public void validate(
      @NonNull INodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    try {
      item.accept(new Visitor(), dynamicContext);
    } catch (WrappedException ex) {
      ex.unwrapAndThrow(ConstraintValidationException.class);
    }
  }

  /**
   * Validate the provided flag item against any associated constraints.
   *
   * @param item
   *          the flag item to validate
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws MetapathException
   *           if an error occurred while evaluating a Metapath used in a
   *           constraint
   */
  protected void validateFlag(
      @NonNull IFlagNodeItem item,
      @NonNull DynamicContext dynamicContext) {
    IFlagDefinition definition = item.getDefinition();

    try {
      validateExpect(definition.getExpectConstraints(), item, dynamicContext);
      validateAllowedValues(definition.getAllowedValuesConstraints(), item, dynamicContext);
      validateIndexHasKey(definition.getIndexHasKeyConstraints(), item, dynamicContext);
      validateMatches(definition.getMatchesConstraints(), item, dynamicContext);
    } catch (ConstraintValidationException ex) {
      throw ExceptionUtils.wrap(ex);
    }
  }

  /**
   * Validate the provided field item against any associated constraints.
   *
   * @param item
   *          the field item to validate
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws MetapathException
   *           if an error occurred while evaluating a Metapath used in a
   *           constraint
   */
  protected void validateField(
      @NonNull IFieldNodeItem item,
      @NonNull DynamicContext dynamicContext) {
    IFieldDefinition definition = item.getDefinition();

    try {
      validateExpect(definition.getExpectConstraints(), item, dynamicContext);
      validateAllowedValues(definition.getAllowedValuesConstraints(), item, dynamicContext);
      validateIndexHasKey(definition.getIndexHasKeyConstraints(), item, dynamicContext);
      validateMatches(definition.getMatchesConstraints(), item, dynamicContext);
    } catch (ConstraintValidationException ex) {
      throw ExceptionUtils.wrap(ex);
    }
  }

  /**
   * Validate the provided assembly item against any associated constraints.
   *
   * @param item
   *          the assembly item to validate
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  protected void validateAssembly(
      @NonNull IAssemblyNodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    IAssemblyDefinition definition = item.getDefinition();

    try {
      validateExpect(definition.getExpectConstraints(), item, dynamicContext);
      validateAllowedValues(definition.getAllowedValuesConstraints(), item, dynamicContext);
      validateIndexHasKey(definition.getIndexHasKeyConstraints(), item, dynamicContext);
      validateMatches(definition.getMatchesConstraints(), item, dynamicContext);
      validateHasCardinality(definition.getHasCardinalityConstraints(), item, dynamicContext);
      validateIndex(definition.getIndexConstraints(), item, dynamicContext);
      validateUnique(definition.getUniqueConstraints(), item, dynamicContext);
    } catch (ConstraintValidationException ex) {
      throw ExceptionUtils.wrap(ex);
    }
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateHasCardinality(
      @NonNull List<? extends ICardinalityConstraint> constraints,
      @NonNull IAssemblyNodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (ICardinalityConstraint constraint : constraints) {
      assert constraint != null;
      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateHasCardinality(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateHasCardinality(
      @NonNull ICardinalityConstraint constraint,
      @NonNull IAssemblyNodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    int itemCount = targets.size();

    IConstraintValidationHandler handler = getConstraintValidationHandler();

    boolean violation = false;
    Integer minOccurs = constraint.getMinOccurs();
    if (minOccurs != null && itemCount < minOccurs) {
      handler.handleCardinalityMinimumViolation(constraint, node, targets, dynamicContext);
      violation = true;
    }

    Integer maxOccurs = constraint.getMaxOccurs();
    if (maxOccurs != null && itemCount > maxOccurs) {
      handler.handleCardinalityMaximumViolation(constraint, node, targets, dynamicContext);
      violation = true;
    }

    if (!violation) {
      handlePass(constraint, node, node, dynamicContext);
    }
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateIndex(
      @NonNull List<? extends IIndexConstraint> constraints,
      @NonNull IAssemblyNodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (IIndexConstraint constraint : constraints) {
      assert constraint != null;

      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateIndex(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateIndex(
      @NonNull IIndexConstraint constraint,
      @NonNull IAssemblyNodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    IConstraintValidationHandler handler = getConstraintValidationHandler();
    if (indexNameToIndexMap.containsKey(constraint.getName())) {
      handler.handleIndexDuplicateViolation(constraint, node, dynamicContext);
    } else {
      validateIndexEntries(constraint, node, targets, dynamicContext);
    }
  }

  private void validateIndexEntries(
      @NonNull IIndexConstraint constraint,
      @NonNull IAssemblyNodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    IIndex index = IIndex.newInstance(constraint.getKeyFields());
    for (INodeItem item : targets) {
      assert item != null;
      if (item.hasValue()) {
        INodeItem oldItem = null;
        try {
          oldItem = index.put(item, IIndex.toKey(item, index.getKeyFields(), dynamicContext));
        } catch (IllegalArgumentException ex) {
          // throw by IIndex.toKey
          handleError(constraint, item, ex, dynamicContext);
        }
        try {
          if (oldItem == null) {
            handlePass(constraint, node, item, dynamicContext);
          } else {
            handler.handleIndexDuplicateKeyViolation(constraint, node, oldItem, item, dynamicContext);
          }
        } catch (MetapathException ex) {
          handler.handleKeyMatchError(constraint, node, item, ex, dynamicContext);
        }
      }
    }
    indexNameToIndexMap.put(constraint.getName(), index);
  }

  private void handlePass(
      @NonNull IConstraint constraint,
      @NonNull INodeItem node,
      @NonNull INodeItem item,
      @NonNull DynamicContext dynamicContext) {
    if (isFeatureEnabled(ValidationFeature.VALIDATE_GENERATE_PASS_FINDINGS)) {
      getConstraintValidationHandler().handlePass(constraint, node, item, dynamicContext);
    }
  }

  private void handleError(
      @NonNull IConstraint constraint,
      @NonNull INodeItem node,
      @NonNull Throwable ex,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    if (isFeatureEnabled(ValidationFeature.THROW_EXCEPTION_ON_ERROR)) {
      if (ex instanceof ConstraintValidationException) {
        throw (ConstraintValidationException) ex;
      }
      throw new ConstraintValidationException(ex);
    }
    getConstraintValidationHandler()
        .handleError(constraint, node, toErrorMessage(constraint, node, ex), ex, dynamicContext);
  }

  @NonNull
  private static String toErrorMessage(
      @NonNull IConstraint constraint,
      @NonNull INodeItem item,
      @NonNull Throwable ex) {
    StringBuilder builder = new StringBuilder(128);
    builder.append("A ")
        .append(constraint.getType().getName())
        .append(" constraint");

    String id = constraint.getId();
    if (id == null) {
      builder.append(" targeting the metapath '")
          .append(constraint.getTarget().getPath())
          .append('\'');
    } else {
      builder.append(" with id '")
          .append(id)
          .append('\'');
    }

    builder.append(", matching the item at path '")
        .append(item.getMetapath())
        .append("', resulted in an unexpected error. ")
        .append(ex.getLocalizedMessage());
    return ObjectUtils.notNull(builder.toString());
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateUnique(
      @NonNull List<? extends IUniqueConstraint> constraints,
      @NonNull IAssemblyNodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (IUniqueConstraint constraint : constraints) {
      assert constraint != null;

      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateUnique(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateUnique(
      @NonNull IUniqueConstraint constraint,
      @NonNull IAssemblyNodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {

    IConstraintValidationHandler handler = getConstraintValidationHandler();
    IIndex index = IIndex.newInstance(constraint.getKeyFields());

    for (INodeItem item : targets) {
      assert item != null;
      if (item.hasValue()) {
        INodeItem oldItem = null;
        try {
          oldItem = index.put(item, IIndex.toKey(item, index.getKeyFields(), dynamicContext));
        } catch (IllegalArgumentException ex) {
          // raised by IIndex.toKey
          handleError(constraint, item, ex, dynamicContext);
        }

        try {
          if (oldItem == null) {
            handlePass(constraint, node, item, dynamicContext);
          } else {
            handler.handleUniqueKeyViolation(constraint, node, oldItem, item, dynamicContext);
          }
        } catch (MetapathException ex) {
          handleError(constraint, item, ex, dynamicContext);
        }
      }
    }
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateMatches(
      @NonNull List<? extends IMatchesConstraint> constraints,
      @NonNull IDefinitionNodeItem<?, ?> item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {

    for (IMatchesConstraint constraint : constraints) {
      assert constraint != null;

      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateMatches(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateMatches(
      @NonNull IMatchesConstraint constraint,
      @NonNull INodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (INodeItem item : targets) {
      assert item != null;
      if (item.hasValue()) {
        validateMatchesItem(constraint, node, item, dynamicContext);
      }
    }
  }

  private void validateMatchesItem(
      @NonNull IMatchesConstraint constraint,
      @NonNull INodeItem node,
      @NonNull INodeItem item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    String value = item.toAtomicItem().asString();

    IConstraintValidationHandler handler = getConstraintValidationHandler();
    boolean valid = true;
    Pattern pattern = constraint.getPattern();
    if (pattern != null && !pattern.asMatchPredicate().test(value)) {
      // failed pattern match
      handler.handleMatchPatternViolation(constraint, node, item, value, pattern, dynamicContext);
      valid = false;
    }

    IDataTypeAdapter<?> adapter = constraint.getDataType();
    if (adapter != null) {
      try {
        adapter.parse(value);
      } catch (IllegalArgumentException ex) {
        handler.handleMatchDatatypeViolation(constraint, node, item, value, adapter, ex, dynamicContext);
        valid = false;
      }
    }

    if (valid) {
      handlePass(constraint, node, item, dynamicContext);
    }
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateIndexHasKey(
      @NonNull List<? extends IIndexHasKeyConstraint> constraints,
      @NonNull IDefinitionNodeItem<?, ?> item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {

    for (IIndexHasKeyConstraint constraint : constraints) {
      assert constraint != null;

      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateIndexHasKey(constraint, item, targets);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   */
  private void validateIndexHasKey(
      @NonNull IIndexHasKeyConstraint constraint,
      @NonNull IDefinitionNodeItem<?, ?> node,
      @NonNull ISequence<? extends INodeItem> targets) {
    String indexName = constraint.getIndexName();

    List<KeyRef> keyRefItems = indexNameToKeyRefMap.get(indexName);
    if (keyRefItems == null) {
      keyRefItems = new LinkedList<>();
      indexNameToKeyRefMap.put(indexName, keyRefItems);
    }

    keyRefItems.add(new KeyRef(constraint, node, new ArrayList<>(targets)));
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateExpect(
      @NonNull List<? extends IExpectConstraint> constraints,
      @NonNull IDefinitionNodeItem<?, ?> item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (IExpectConstraint constraint : constraints) {
      assert constraint != null;

      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateExpect(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateExpect(
      @NonNull IExpectConstraint constraint,
      @NonNull INodeItem node,
      @NonNull ISequence<? extends INodeItem> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    IMetapathExpression test = constraint.getTest();
    IConstraintValidationHandler handler = getConstraintValidationHandler();
    for (INodeItem item : targets) {
      assert item != null;

      if (item.hasValue()) {
        try {
          ISequence<?> result = test.evaluate(item, dynamicContext);
          if (FnBoolean.fnBoolean(result).toBoolean()) {
            handlePass(constraint, node, item, dynamicContext);
          } else {
            handler.handleExpectViolation(constraint, node, item, dynamicContext);
          }
        } catch (MetapathException ex) {
          handleError(constraint, item, ex, dynamicContext);
        }
      }
    }
  }

  /**
   * Evaluates the provided collection of {@code constraints} in the context of
   * the {@code item}.
   *
   * @param constraints
   *          the constraints to execute
   * @param item
   *          the focus of Metapath evaluation
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateAllowedValues(
      @NonNull List<? extends IAllowedValuesConstraint> constraints,
      @NonNull IDefinitionNodeItem<?, ?> item,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (IAllowedValuesConstraint constraint : constraints) {
      assert constraint != null;
      try {
        ISequence<? extends IDefinitionNodeItem<?, ?>> targets = constraint.matchTargets(item, dynamicContext);
        validateAllowedValues(constraint, item, targets, dynamicContext);
      } catch (MetapathException ex) {
        handleError(constraint, item, ex, dynamicContext);
      }
    }
  }

  /**
   * Evaluates the provided {@code constraint} against each of the
   * {@code targets}.
   *
   * @param constraint
   *          the constraint to execute
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @param targets
   *          the focus of Metapath evaluation for evaluating any constraint
   *          Metapath clauses
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while validating a constraint
   */
  private void validateAllowedValues(
      @NonNull IAllowedValuesConstraint constraint,
      @NonNull IDefinitionNodeItem<?, ?> node,
      @NonNull ISequence<? extends IDefinitionNodeItem<?, ?>> targets,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    for (INodeItem item : targets) {
      assert item != null;
      if (item.hasValue()) {
        try {
          updateValueStatus(item, constraint, node);
        } catch (ConstraintValidationException ex) {
          handleError(constraint, item, ex, dynamicContext);
        }
      }
    }
  }

  /**
   * Add a new allowed value to the value status tracker.
   *
   * @param targetItem
   *          the item whose value is targeted by the constraint
   * @param allowedValues
   *          the allowed values constraint
   * @param node
   *          the original focus of Metapath evaluation for identifying the
   *          targets
   * @throws ConstraintValidationException
   *           if an unexpected error occurred while registering the allowed
   *           values
   */
  protected void updateValueStatus(
      @NonNull INodeItem targetItem,
      @NonNull IAllowedValuesConstraint allowedValues,
      @NonNull IDefinitionNodeItem<?, ?> node) throws ConstraintValidationException {
    // constraint.getAllowedValues().containsKey(value)

    @Nullable
    ValueStatus valueStatus = valueMap.get(targetItem);
    if (valueStatus == null) {
      valueStatus = new ValueStatus(targetItem);
      valueMap.put(targetItem, valueStatus);
    }

    valueStatus.registerAllowedValues(allowedValues, node);
  }

  /**
   * Evaluate the value associated with the {@code targetItem} and update the
   * status tracker.
   *
   * @param targetItem
   *          the item whose value will be validated
   * @param dynamicContext
   *          the Metapath dynamic execution context to use for Metapath
   *          evaluation
   */
  protected void handleAllowedValues(
      @NonNull INodeItem targetItem,
      @NonNull DynamicContext dynamicContext) {
    ValueStatus valueStatus = valueMap.remove(targetItem);
    if (valueStatus != null) {
      valueStatus.validate(dynamicContext);
    }
  }

  @Override
  public void finalizeValidation(DynamicContext dynamicContext) throws ConstraintValidationException {
    // key references
    for (Map.Entry<String, List<KeyRef>> entry : indexNameToKeyRefMap.entrySet()) {
      String indexName = ObjectUtils.notNull(entry.getKey());
      IIndex index = indexNameToIndexMap.get(indexName);

      List<KeyRef> keyRefs = entry.getValue();

      for (KeyRef keyRef : keyRefs) {
        IIndexHasKeyConstraint constraint = keyRef.getConstraint();

        INodeItem node = keyRef.getNode();
        List<INodeItem> targets = keyRef.getTargets();
        for (INodeItem item : targets) {
          assert item != null;
          try {
            validateKeyRef(constraint, node, item, indexName, index, dynamicContext);
          } catch (MetapathException ex) {
            handleError(constraint, item, ex, dynamicContext);
          }
        }
      }
    }
  }

  private void validateKeyRef(
      @NonNull IIndexHasKeyConstraint constraint,
      @NonNull INodeItem contextNode,
      @NonNull INodeItem item,
      @NonNull String indexName,
      @Nullable IIndex index,
      @NonNull DynamicContext dynamicContext) throws ConstraintValidationException {
    IConstraintValidationHandler handler = getConstraintValidationHandler();
    try {
      List<String> key;
      try {
        key = IIndex.toKey(item, constraint.getKeyFields(), dynamicContext);
      } catch (IllegalArgumentException ex) {
        handler.handleError(constraint, item, toErrorMessage(constraint, item, ex), ex, dynamicContext);
        throw ex;
      }

      if (index == null) {
        handler.handleMissingIndexViolation(
            constraint,
            contextNode,
            item,
            ObjectUtils.notNull(String.format("Key reference to undefined index with name '%s'",
                indexName)),
            dynamicContext);
      } else {
        INodeItem referencedItem = index.get(key);

        if (referencedItem == null) {
          handler.handleIndexMiss(constraint, contextNode, item, key, dynamicContext);
        } else {
          handlePass(constraint, contextNode, item, dynamicContext);
        }
      }
    } catch (MetapathException ex) {
      handler.handleKeyMatchError(constraint, contextNode, item, ex, dynamicContext);
    }
  }

  private class ValueStatus {
    @NonNull
    private final List<Pair<IAllowedValuesConstraint, IDefinitionNodeItem<?, ?>>> constraints = new LinkedList<>();
    @NonNull
    private final String value;
    @NonNull
    private final INodeItem item;
    private boolean allowOthers = true;
    @NonNull
    private IAllowedValuesConstraint.Extensible extensible = IAllowedValuesConstraint.Extensible.EXTERNAL;

    public ValueStatus(@NonNull INodeItem item) {
      this.item = item;
      this.value = item.toAtomicItem().asString();
    }

    public void registerAllowedValues(
        @NonNull IAllowedValuesConstraint allowedValues,
        @NonNull IDefinitionNodeItem<?, ?> node) throws ConstraintValidationException {
      IAllowedValuesConstraint.Extensible newExtensible = allowedValues.getExtensible();
      if (newExtensible.ordinal() > extensible.ordinal()) {
        // record the most restrictive value
        extensible = allowedValues.getExtensible();
      } else if (IAllowedValuesConstraint.Extensible.NONE.equals(newExtensible)
          && IAllowedValuesConstraint.Extensible.NONE.equals(extensible)) {
        // this is an error, where there are two none constraints that conflict
        // TODO: find a different exception type to use
        throw new ConstraintValidationException(
            ObjectUtils.notNull(String.format(
                "Multiple constraints matching path '%s' have scope='none', which prevents extension. Involved" +
                    " constraints are: %s",
                Stream.concat(
                    Stream.of(allowedValues),
                    constraints.stream()
                        .map(Pair::getLeft)
                        .filter(
                            constraint -> IAllowedValuesConstraint.Extensible.NONE.equals(constraint.getExtensible())))
                    .map(IConstraint::getConstraintIdentity)
                    .collect(Collectors.joining(", ", "{", "}")),
                item.getMetapath())));
      } else if (allowedValues.getExtensible().ordinal() < extensible.ordinal()) {
        String msg = ObjectUtils.notNull(String.format(
            "An allowed values constraint with an extensibility scope '%s'"
                + " exceeds the allowed scope '%s' at path '%s'",
            allowedValues.getExtensible().name(), extensible.name(), item.getMetapath()));
        LOGGER.atError().log(msg);
        throw new ConstraintValidationException(msg);
      }
      this.constraints.add(Pair.of(allowedValues, node));
      if (!allowedValues.isAllowedOther()) {
        // record the most restrictive value
        allowOthers = false;
      }
    }

    public void validate(@NonNull DynamicContext dynamicContext) {
      if (!constraints.isEmpty()) {
        boolean match = false;
        List<IAllowedValuesConstraint> failedConstraints = new LinkedList<>();
        IConstraintValidationHandler handler = getConstraintValidationHandler();
        for (Pair<IAllowedValuesConstraint, IDefinitionNodeItem<?, ?>> pair : constraints) {
          IAllowedValuesConstraint allowedValues = pair.getLeft();
          IDefinitionNodeItem<?, ?> node = ObjectUtils.notNull(pair.getRight());
          IAllowedValue matchingValue = allowedValues.getAllowedValue(value);
          if (matchingValue != null) {
            match = true;
            handlePass(allowedValues, node, item, dynamicContext);
          } else if (IAllowedValuesConstraint.Extensible.NONE.equals(allowedValues.getExtensible())) {
            // hard failure, since no other values can satisfy this constraint
            failedConstraints = CollectionUtil.singletonList(allowedValues);
            match = false;
            break;
          } else {
            failedConstraints.add(allowedValues);
          } // this constraint passes, but we need to make sure other constraints do as well
        }

        // it's not a failure if allow others is true
        if (!match && !allowOthers) {
          handler.handleAllowedValuesViolation(failedConstraints, item, dynamicContext);
        }
      }
    }
  }

  class Visitor
      extends AbstractNodeItemVisitor<DynamicContext, Void> {

    @NonNull
    private DynamicContext handleLetStatements(
        @NonNull INodeItem focus,
        @NonNull Map<IEnhancedQName, ILet> letExpressions,
        @NonNull DynamicContext dynamicContext) {

      DynamicContext retval;
      Collection<ILet> lets = letExpressions.values();
      if (lets.isEmpty()) {
        retval = dynamicContext;
      } else {
        final DynamicContext subContext = dynamicContext.subContext();

        for (ILet let : lets) {
          IEnhancedQName name = let.getName();
          ISequence<?> result = let.getValueExpression().evaluate(focus, subContext);
          subContext.bindVariableValue(
              name,
              // ensure the sequence is list backed
              result.reusable());
        }
        retval = subContext;
      }
      return retval;
    }

    @Override
    public Void visitFlag(@NonNull IFlagNodeItem item, DynamicContext context) {
      assert context != null;

      IFlagDefinition definition = item.getDefinition();
      DynamicContext effectiveContext = handleLetStatements(item, definition.getLetExpressions(), context);

      validateFlag(item, effectiveContext);
      super.visitFlag(item, effectiveContext);
      handleAllowedValues(item, context);
      return null;
    }

    @Override
    public Void visitField(@NonNull IFieldNodeItem item, DynamicContext context) {
      assert context != null;

      IFieldDefinition definition = item.getDefinition();
      DynamicContext effectiveContext = handleLetStatements(item, definition.getLetExpressions(), context);

      validateField(item, effectiveContext);
      super.visitField(item, effectiveContext);
      handleAllowedValues(item, context);
      return null;
    }

    @Override
    public Void visitAssembly(@NonNull IAssemblyNodeItem item, DynamicContext context) {
      assert context != null;

      IAssemblyDefinition definition = item.getDefinition();
      DynamicContext effectiveContext = handleLetStatements(item, definition.getLetExpressions(), context);

      try {
        validateAssembly(item, effectiveContext);
      } catch (ConstraintValidationException ex) {
        throw ExceptionUtils.wrap(ex);
      }
      super.visitAssembly(item, effectiveContext);
      return null;
    }

    @Override
    public Void visitMetaschema(@NonNull IModuleNodeItem item, DynamicContext context) {
      throw new UnsupportedOperationException("Method not used.");
    }

    @Override
    protected Void defaultResult() {
      // no result value
      return null;
    }
  }

  private static class KeyRef {
    @NonNull
    private final IIndexHasKeyConstraint constraint;
    @NonNull
    private final INodeItem node;
    @NonNull
    private final List<INodeItem> targets;

    public KeyRef(
        @NonNull IIndexHasKeyConstraint constraint,
        @NonNull INodeItem node,
        @NonNull List<INodeItem> targets) {
      this.node = node;
      this.constraint = constraint;
      this.targets = targets;
    }

    @NonNull
    public IIndexHasKeyConstraint getConstraint() {
      return constraint;
    }

    @NonNull
    protected INodeItem getNode() {
      return node;
    }

    @NonNull
    public List<INodeItem> getTargets() {
      return targets;
    }
  }
}
