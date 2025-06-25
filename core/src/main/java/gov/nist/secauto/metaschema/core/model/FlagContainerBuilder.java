/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.model.impl.DefaultContainerFlagSupport;
import gov.nist.secauto.metaschema.core.qname.EQNameFactory;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public class FlagContainerBuilder<T extends IFlagInstance> implements IFlagContainerBuilder<T> {
  private static final Logger LOGGER = LogManager.getLogger(FlagContainerBuilder.class);

  @Nullable
  private final Integer jsonKeyIndex;
  @NonNull
  private final List<T> flags;

  /**
   * Construct a new flag container using the provided flag qualified name as the
   * JSON key.
   *
   * @param jsonKeyIndex
   *          the qualified name index of the JSON key or {@code null} if no JSON
   *          key is configured
   */
  public FlagContainerBuilder(@Nullable Integer jsonKeyIndex) {
    this.jsonKeyIndex = jsonKeyIndex;
    this.flags = new LinkedList<>();
  }

  @Override
  @NonNull
  public IFlagContainerBuilder<T> flag(@NonNull T instance) {
    flags.add(instance);
    return this;
  }

  @Override
  public IContainerFlagSupport<T> build() {
    IContainerFlagSupport<T> retval;
    if (flags.isEmpty()) {
      retval = IContainerFlagSupport.empty();
    } else {
      Map<Integer, T> flagMap = CollectionUtil.unmodifiableMap(ObjectUtils.notNull(flags.stream()
          .collect(
              CustomCollectors.toMap(
                  flag -> flag.getQName().getIndexPosition(),
                  CustomCollectors.identity(),
                  FlagContainerBuilder::handleShadowedInstances,
                  LinkedHashMap::new))));

      T jsonKey = jsonKeyIndex == null ? null : flagMap.get(jsonKeyIndex);
      retval = new DefaultContainerFlagSupport<>(flagMap, jsonKey);
    }
    return retval;
  }

  private static <INSTANCE extends IFlagInstance> INSTANCE handleShadowedInstances(
      @NonNull Integer keyIndex,
      @NonNull INSTANCE shadowed,
      @NonNull INSTANCE shadowing) {
    if (!shadowed.equals(shadowing) && LOGGER.isErrorEnabled()) {
      IModelDefinition owningDefinition = shadowing.getContainingDefinition();
      IModule module = owningDefinition.getContainingModule();
      LOGGER.error("Unexpected duplicate flag instance name '%s' in definition '%s' in module name '%s' at '%s'",
          EQNameFactory.instance().get(keyIndex).or(null),
          owningDefinition.getDefinitionQName(),
          module.getShortName(),
          module.getLocation());
    }
    return shadowing;
  }
}
