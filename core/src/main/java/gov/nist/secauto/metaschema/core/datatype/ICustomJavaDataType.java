/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * The common interface for all data type implementations supported by a custom
 * Java class.
 *
 * @param <TYPE>
 *          the type of the custom Java class
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface ICustomJavaDataType<TYPE extends ICustomJavaDataType<TYPE>> {
  /**
   * Provides a copy of the data value associated with the Datatype instance.
   *
   * @return the copy
   */
  @NonNull
  TYPE copy();
}
