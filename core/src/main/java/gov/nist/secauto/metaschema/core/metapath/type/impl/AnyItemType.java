/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.type.AbstractItemTypeBase;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * An item type that applies to all items.
 */
@SuppressFBWarnings(value = "SING_SINGLETON_GETTER_NOT_SYNCHRONIZED", justification = "false positive")
public final class AnyItemType
    extends AbstractItemTypeBase {
  @NonNull
  private static final AnyItemType INSTANCE = new AnyItemType();

  /**
   * Get the singleton instance.
   *
   * @return the singleton instance
   */
  @NonNull
  public static AnyItemType instance() {
    return INSTANCE;
  }

  @Override
  public boolean isInstance(IItem item) {
    // any item type always matches
    return true;
  }

  @Override
  public Class<? extends IItem> getItemClass() {
    return IItem.class;
  }

  @Override
  public String generateSignature() {
    return "item()";
  }

  private AnyItemType() {
    // disable construction
  }
}
