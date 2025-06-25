/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.model.IValued;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IValuedMutable extends IValued {
  /**
   * Set the provided value on the provided object. The provided object must be of
   * the item's type associated with this instance.
   *
   * @param parentObject
   *          the object
   * @param value
   *          a value, which may be a simple {@link Type} or a
   *          {@link ParameterizedType} for a collection
   */
  void setValue(@NonNull Object parentObject, Object value);
}
