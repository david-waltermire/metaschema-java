/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IMetapathQueryable {
  /**
   * Get the Metapath node item for this Metaschema module construct, which can be
   * used to query it.
   *
   * @return the node item
   */
  @NonNull
  INodeItem getNodeItem();
}
