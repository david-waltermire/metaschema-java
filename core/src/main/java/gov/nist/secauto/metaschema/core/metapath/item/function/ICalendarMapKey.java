/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.function;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.ICalendarTemporalItem;

/**
 * An {@link IMapItem} key based on an {@link ICalendarTemporalItem}.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface ICalendarMapKey extends ITemporalMapKey {
  @Override
  ICalendarTemporalItem getKey();
}
