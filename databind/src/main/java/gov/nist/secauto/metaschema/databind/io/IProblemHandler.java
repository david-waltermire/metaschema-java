/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundProperty;

import java.io.IOException;
import java.util.Collection;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implementations support handling common parsing issues.
 */
// TODO: consider what methods can be defined here
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IProblemHandler {
  /**
   * A callback used to handle bound properties for which no data was found when
   * the content was parsed.
   * <p>
   * This can be used to supply default or prescribed values based on application
   * logic.
   *
   * @param parentDefinition
   *          the bound class on which the missing properties are found
   * @param targetObject
   *          the Java object for the {@code parentDefinition}
   * @param unhandledInstances
   *          the set of instances that had no data to parse
   * @throws IOException
   *           if an error occurred while handling the missing instances
   */
  void handleMissingInstances(
      @NonNull IBoundDefinitionModelComplex parentDefinition,
      @NonNull IBoundObject targetObject,
      @NonNull Collection<? extends IBoundProperty<?>> unhandledInstances)
      throws IOException;
}
