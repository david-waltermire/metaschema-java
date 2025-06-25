/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import java.lang.reflect.Field;
import java.lang.reflect.Type;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IFeatureJavaField extends IValuedMutable {

  /**
   * Gets the bound Java field associated with this instance.
   *
   * @return the Java field
   */
  @NonNull
  Field getField();

  /**
   * Get the actual Java type of the underlying bound object.
   * <p>
   * This may be the same as the what is returned by {@link #getItemType()}, or
   * may be a Java collection class.
   *
   * @return the raw type of the bound object
   */
  @SuppressWarnings("null")
  @NonNull
  default Type getType() {
    return getField().getGenericType();
  }

  /**
   * Get the item type of the bound object. An item type is the primitive or
   * specialized type that represents that data associated with this binding.
   *
   * @return the item type of the bound object
   */
  @NonNull
  default Class<?> getItemType() {
    return (Class<?>) getType();
  }

  @Override
  default Object getValue(@NonNull Object parent) {
    Field field = getField();
    Object retval;
    try {
      Object result = field.get(parent);
      retval = result;
    } catch (IllegalArgumentException | IllegalAccessException ex) {
      throw new IllegalArgumentException(
          String.format("Unable to get the value of field '%s' in class '%s'.", field.getName(),
              field.getDeclaringClass().getName()),
          ex);
    }
    return retval;
  }

  @Override
  default void setValue(@NonNull Object parentObject, Object value) {
    Field field = getField();
    try {
      field.set(parentObject, value);
    } catch (IllegalArgumentException | IllegalAccessException ex) {
      throw new IllegalArgumentException(
          String.format(
              "Unable to set the value of field '%s' in class '%s'." +
                  " Perhaps this is a data type adapter problem on the declared class?",
              field.getName(),
              field.getDeclaringClass().getName()),
          ex);
    }
  }

}
