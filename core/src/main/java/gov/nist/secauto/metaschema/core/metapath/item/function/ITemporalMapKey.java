/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.ITemporalItem;

/**
 * An {@link IMapItem} key based on an {@link ITemporalItem} value.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface ITemporalMapKey extends IMapKey {

  @Override
  ITemporalItem getKey();

  @Override
  @SuppressWarnings("PMD.OnlyOneReturn")
  default boolean isSameKey(IMapKey other) {
    if (!(other instanceof ITemporalMapKey)) {
      return false;
    }

    ITemporalItem thisTemporal = getKey();
    ITemporalItem otherTemporal = ((ITemporalMapKey) other).getKey();
    return thisTemporal.hasTimezone() == otherTemporal.hasTimezone()
        && thisTemporal.deepEquals(otherTemporal);
  }
}
