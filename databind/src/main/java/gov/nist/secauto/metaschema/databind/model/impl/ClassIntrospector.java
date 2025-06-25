/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public final class ClassIntrospector {
  private ClassIntrospector() {
    // disable construction
  }

  public static List<Method> getMatchingMethods(Class<?> clazz, String name, Class<?>... parameterTypes) {
    List<Method> retval = new LinkedList<>();
    Class<?> searchClass = clazz;
    do {
      try {
        Method method = searchClass.getDeclaredMethod(name, parameterTypes);
        retval.add(method);
      } catch (NoSuchMethodException ex) {
        // do nothing, no matching method was found
      }
    } while ((searchClass = searchClass.getSuperclass()) != null);

    return retval.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(retval);
  }

  public static Method getMatchingMethod(Class<?> clazz, String name, Class<?>... parameterTypes) {
    Method retval = null;
    Class<?> searchClass = clazz;
    do {
      try {
        retval = searchClass.getDeclaredMethod(name, parameterTypes);
        // stop on first found method
        break;
      } catch (NoSuchMethodException ex) {
        // do nothing, no matching method was found
      }
    } while ((searchClass = searchClass.getSuperclass()) != null);

    return retval;
  }
}
