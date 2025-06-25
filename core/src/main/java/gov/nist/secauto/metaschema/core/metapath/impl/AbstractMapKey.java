/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.impl;

import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;

import nl.talsmasoftware.lazy4j.Lazy;

public abstract class AbstractMapKey implements IMapKey {
  private final Lazy<Integer> hashCode = Lazy.of(this::generateHashCode);

  @Override
  public int hashCode() {
    return hashCode.get();
  }

  /**
   * Generate the hash code for the key.
   *
   * @return the hash code
   */
  protected int generateHashCode() {
    return getKey().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IMapKey && isSameKey((IMapKey) obj);
  }

  @Override
  public String toString() {
    return getKey().toSignature();
  }
}
