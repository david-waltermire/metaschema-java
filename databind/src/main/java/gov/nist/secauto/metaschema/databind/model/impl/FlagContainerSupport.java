/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.model.IContainerFlagSupport;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.BoundFlag;
import gov.nist.secauto.metaschema.databind.model.annotations.Ignore;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class FlagContainerSupport implements IContainerFlagSupport<IBoundInstanceFlag> {
  @NonNull
  private final Map<Integer, IBoundInstanceFlag> flagInstances;
  @Nullable
  private IBoundInstanceFlag jsonKeyFlag;

  @SuppressFBWarnings(value = "CT_CONSTRUCTOR_THROW", justification = "Use of final fields")
  public FlagContainerSupport(
      @NonNull IBoundDefinitionModelComplex definition,
      @Nullable Consumer<IBoundInstanceFlag> peeker) {
    Class<?> clazz = definition.getBoundClass();

    Stream<IBoundInstanceFlag> instances = getFlagInstanceFields(clazz).stream()
        .flatMap(field -> {
          Stream<IBoundInstanceFlag> stream;
          if (field.isAnnotationPresent(BoundFlag.class)) {
            stream = Stream.of(IBoundInstanceFlag.newInstance(field, definition));
          } else {
            stream = Stream.empty();
          }
          return stream;
        });

    Consumer<IBoundInstanceFlag> intermediate = this::handleFlagInstance;

    if (peeker != null) {
      intermediate = intermediate.andThen(peeker);
    }

    this.flagInstances = CollectionUtil.unmodifiableMap(ObjectUtils.notNull(instances
        .peek(intermediate)
        .collect(Collectors.toMap(
            flag -> flag.getQName().getIndexPosition(),
            Function.identity(),
            (v1, v2) -> v2,
            LinkedHashMap::new))));
  }

  /**
   * Collect all fields that are flag instances on this class.
   *
   * @param clazz
   *          the class
   * @return an immutable collection of flag instances
   */
  @SuppressWarnings("PMD.UseArraysAsList")
  @NonNull
  protected static Collection<Field> getFlagInstanceFields(Class<?> clazz) {
    Field[] fields = clazz.getDeclaredFields();

    List<Field> retval = new LinkedList<>();

    Class<?> superClass = clazz.getSuperclass();
    if (superClass != null) {
      // get flags from superclass
      retval.addAll(getFlagInstanceFields(superClass));
    }

    for (Field field : fields) {
      if (!field.isAnnotationPresent(BoundFlag.class) || field.isAnnotationPresent(Ignore.class)) {
        // skip this field, since it is ignored
        continue;
      }

      retval.add(field);
    }
    return ObjectUtils.notNull(Collections.unmodifiableCollection(retval));
  }

  /**
   * Used to delegate flag instance initialization to subclasses.
   *
   * @param instance
   *          the flag instance to process
   */
  protected void handleFlagInstance(IBoundInstanceFlag instance) {
    if (instance.isJsonKey()) {
      this.jsonKeyFlag = instance;
    }
  }

  @Override
  @NonNull
  public Map<Integer, IBoundInstanceFlag> getFlagInstanceMap() {
    return flagInstances;
  }

  @Override
  public IBoundInstanceFlag getJsonKeyFlagInstance() {
    return jsonKeyFlag;
  }
}
