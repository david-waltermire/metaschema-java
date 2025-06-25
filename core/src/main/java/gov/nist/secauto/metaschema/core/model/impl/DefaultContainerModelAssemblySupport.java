/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.impl;

import gov.nist.secauto.metaschema.core.model.IAssemblyInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelAssemblySupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;
import gov.nist.secauto.metaschema.core.model.IModelInstance;
import gov.nist.secauto.metaschema.core.model.INamedModelInstance;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Supports model instance operations on assembly model instances.
 * <p>
 * This implementation uses underlying {@link LinkedHashMap} instances to
 * preserve ordering.
 *
 * @param <MI>
 *          the model instance Java type
 * @param <NMI>
 *          the named model instance Java type
 * @param <FI>
 *          the field instance Java type
 * @param <AI>
 *          the assembly instance Java type
 * @param <CI>
 *          the choice instance Java type
 * @param <CGI>
 *          the choice group instance Java type
 */
public class DefaultContainerModelAssemblySupport<
    MI extends IModelInstance,
    NMI extends INamedModelInstance,
    FI extends IFieldInstance,
    AI extends IAssemblyInstance,
    CI extends IChoiceInstance,
    CGI extends IChoiceGroupInstance>
    extends DefaultContainerModelSupport<MI, NMI, FI, AI>
    implements IContainerModelAssemblySupport<MI, NMI, FI, AI, CI, CGI> {

  /**
   * An empty, immutable container.
   */
  @SuppressWarnings("rawtypes")
  @NonNull
  public static final DefaultContainerModelAssemblySupport EMPTY = new DefaultContainerModelAssemblySupport<>(
      CollectionUtil.emptyList(),
      CollectionUtil.emptyMap(),
      CollectionUtil.emptyMap(),
      CollectionUtil.emptyMap(),
      CollectionUtil.emptyList(),
      CollectionUtil.emptyMap());

  @NonNull
  private final List<CI> choiceInstances;
  @NonNull
  private final Map<String, CGI> choiceGroupInstances;

  /**
   * Construct an empty, mutable container.
   */
  public DefaultContainerModelAssemblySupport() {
    this(
        new LinkedList<>(),
        new LinkedHashMap<>(),
        new LinkedHashMap<>(),
        new LinkedHashMap<>(),
        new LinkedList<>(),
        new LinkedHashMap<>());
  }

  /**
   * Construct an new container using the provided collections.
   *
   * @param instances
   *          a collection of model instances
   * @param namedModelInstances
   *          a collection of named model instances
   * @param fieldInstances
   *          a collection of field instances
   * @param assemblyInstances
   *          a collection of assembly instances
   * @param choiceInstances
   *          a collection of choice instances
   * @param choiceGroupInstances
   *          a collection of choice group instances
   */
  public DefaultContainerModelAssemblySupport(
      @NonNull List<MI> instances,
      @NonNull Map<Integer, NMI> namedModelInstances,
      @NonNull Map<Integer, FI> fieldInstances,
      @NonNull Map<Integer, AI> assemblyInstances,
      @NonNull List<CI> choiceInstances,
      @NonNull Map<String, CGI> choiceGroupInstances) {
    super(instances, namedModelInstances, fieldInstances, assemblyInstances);
    this.choiceInstances = choiceInstances;
    this.choiceGroupInstances = choiceGroupInstances;
  }

  @Override
  public List<CI> getChoiceInstances() {
    return choiceInstances;
  }

  @Override
  public Map<String, CGI> getChoiceGroupInstanceMap() {
    return choiceGroupInstances;
  }
}
