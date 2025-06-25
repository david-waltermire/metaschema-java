/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IContainer {
  /**
   * Identifies if the container allows child instances or not.
   * <p>
   * This can be the case if the container has flags or a complex model with at
   * least a choice, choice group, field, or assembly instance.
   *
   * @return {@code true} if there are flags or a model, or {@code false}
   *         otherwise
   */
  boolean hasChildren();
}
