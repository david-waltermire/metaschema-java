/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Supports walking a portion of a metaschema model collecting a set of
 * definitions that match the provided filter. For a definition to be collected,
 * the filter must return {@code true}.
 */
public abstract class DefinitionCollectingModelWalker
    extends ModelWalker<Void> {
  private static final Logger LOGGER = LogManager.getLogger(DefinitionCollectingModelWalker.class);

  private final Function<IDefinition, Boolean> filter;
  @NonNull
  private final Set<IDefinition> definitions = new LinkedHashSet<>();

  @Override
  protected Void getDefaultData() {
    return null;
  }

  /**
   * Construct a new walker using the provided filter.
   *
   * @param filter
   *          the filter to match definitions against
   */
  protected DefinitionCollectingModelWalker(Function<IDefinition, Boolean> filter) {
    Objects.requireNonNull(filter, "filter");
    this.filter = filter;
  }

  /**
   * Retrieves the filter used for matching.
   *
   * @return the filter
   */
  protected Function<IDefinition, Boolean> getFilter() {
    return filter;
  }

  /**
   * Return the collection of definitions matching the configured filter.
   *
   * @return the collection of definitions
   */
  @NonNull
  @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "interface doesn't allow modification")
  public Collection<? extends IDefinition> getDefinitions() {
    return definitions;
  }

  @Override
  protected void visit(IFlagDefinition def, Void data) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("visiting flag definition '{}'", def.toCoordinates());
    }
    if (getFilter().apply(def)) {
      definitions.add(def);
    }
  }

  @Override
  protected boolean visit(IFieldDefinition def, Void data) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("visiting field definition '{}'", def.toCoordinates());
    }
    boolean retval;
    if (definitions.contains(def)) {
      // no need to visit, since this has already been seen
      retval = false;
    } else {
      if (getFilter().apply(def)) {
        definitions.add(def);
      }
      retval = true;
    }
    return retval;
  }

  @Override
  protected boolean visit(IAssemblyDefinition def, Void data) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("visiting assembly definition '{}'", def.toCoordinates());
    }
    boolean retval;
    if (definitions.contains(def)) {
      // no need to visit, since this has already been seen
      retval = false;
    } else {
      if (getFilter().apply(def)) {
        definitions.add(def);
      }
      retval = true;
    }
    return retval;
  }
}
