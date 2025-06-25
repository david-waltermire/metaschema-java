/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IJsonNamed {

  /**
   * Get the name used for the associated property in JSON/YAML
   * serialization-related operations.
   *
   * @return the JSON property name
   */
  @NonNull
  String getJsonName();
}
