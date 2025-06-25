/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import java.util.LinkedHashMap;
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
 */
public abstract class AbstractContainerModelSupport<
    MI extends IModelInstance,
    NMI extends INamedModelInstance,
    FI extends IFieldInstance,
    AI extends IAssemblyInstance>
    implements IContainerModelSupport<MI, NMI, FI, AI> {

  @NonNull
  private final Map<Integer, NMI> namedModelInstances;
  @NonNull
  private final Map<Integer, FI> fieldInstances;
  @NonNull
  private final Map<Integer, AI> assemblyInstances;

  /**
   * Construct an empty, mutable container.
   */
  public AbstractContainerModelSupport() {
    this(
        new LinkedHashMap<>(),
        new LinkedHashMap<>(),
        new LinkedHashMap<>());
  }

  /**
   * Construct an new container using the provided collections.
   *
   * @param namedModelInstances
   *          a collection of named model instances
   * @param fieldInstances
   *          a collection of field instances
   * @param assemblyInstances
   *          a collection of assembly instances
   */
  protected AbstractContainerModelSupport(
      @NonNull Map<Integer, NMI> namedModelInstances,
      @NonNull Map<Integer, FI> fieldInstances,
      @NonNull Map<Integer, AI> assemblyInstances) {
    this.namedModelInstances = namedModelInstances;
    this.fieldInstances = fieldInstances;
    this.assemblyInstances = assemblyInstances;
  }

  @Override
  public Map<Integer, NMI> getNamedModelInstanceMap() {
    return namedModelInstances;
  }

  @Override
  public Map<Integer, FI> getFieldInstanceMap() {
    return fieldInstances;
  }

  @Override
  public Map<Integer, AI> getAssemblyInstanceMap() {
    return assemblyInstances;
  }

  @SuppressWarnings({ "PMD.EmptyFinalizer", "checkstyle:NoFinalizer" })
  @Override
  protected final void finalize() {
    // Address SEI CERT Rule OBJ-11:
    // https://wiki.sei.cmu.edu/confluence/display/java/OBJ11-J.+Be+wary+of+letting+constructors+throw+exceptions
  }
}
