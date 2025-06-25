/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function;

/**
 * Represents a map key with no special handling based on the key value's data
 * type. In this way the key value is essentially "opaque".
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IOpaqueMapKey extends IMapKey {
  @Override
  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  default boolean isSameKey(IMapKey other) {
    return this == other
        || other instanceof IOpaqueMapKey
            && getKey().deepEquals(other.getKey());
  }
}
