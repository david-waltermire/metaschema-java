/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A marker interface for Metaschema constructs that can be members of a
 * Metaschema definition's model.
 */
public interface IModelElement extends IDefaultable, IModelElementVisitable {

  /**
   * Get the Metaschema model type of the information element.
   *
   * @return the type
   */
  @NonNull
  ModelType getModelType();

  /**
   * Retrieves a string that uniquely identifies the model element in the overall
   * collection of model elements. This should the type of element, it's name, and
   * any additional information needed to uniquely identify it.
   *
   * @return the coordinates
   */
  @NonNull
  String toCoordinates();

  /**
   * Retrieve the remarks associated with this information element, if any.
   *
   * @return the remarks or {@code null} if no remarks are defined
   */
  @Nullable
  MarkupMultiline getRemarks();

  /**
   * Retrieves the Metaschema module that contains the information element's
   * declaration.
   *
   * @return the Metaschema module
   */
  // REFACTOR: move to definition
  @NonNull
  IModule getContainingModule();
}
