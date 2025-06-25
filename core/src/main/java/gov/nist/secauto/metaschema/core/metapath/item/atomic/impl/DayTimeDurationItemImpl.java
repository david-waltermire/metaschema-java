/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.adapter.DayTimeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.function.DateTimeFunctionException;
import gov.nist.secauto.metaschema.core.metapath.impl.AbstractMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDayTimeDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.IOpaqueMapKey;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.time.Duration;
import java.time.ZoneOffset;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of a Metapath atomic item containing a duration data value
 * in days, hours, and seconds.
 */
public class DayTimeDurationItemImpl
    extends AbstractDurationItem<Duration>
    implements IDayTimeDurationItem {
  private static final long MIN_OFFSET_SECONDS = -50_400; // -14 hours in seconds
  private static final long MAX_OFFSET_SECONDS = 50_400; // 14 hours in seconds

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public DayTimeDurationItemImpl(@NonNull Duration value) {
    super(value);
  }

  @Override
  public Duration asDuration() {
    return getValue();
  }

  @Override
  public ZoneOffset asZoneOffset() {
    Duration duration = asDuration();
    long seconds = duration.toSeconds();
    if (seconds < MIN_OFFSET_SECONDS || seconds > MAX_OFFSET_SECONDS) {
      throw new DateTimeFunctionException(
          DateTimeFunctionException.INVALID_TIME_ZONE_VALUE_ERROR,
          String.format("The duration '%s' must be >= -PT14H and <= PT13H.", duration.toString()));
    }
    return ObjectUtils.notNull(ZoneOffset.ofTotalSeconds((int) seconds));
  }

  @Override
  public DayTimeAdapter getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.DAY_TIME_DURATION;
  }

  @Override
  public int hashCode() {
    return asDuration().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IDayTimeDurationItem && compareTo((IDayTimeDurationItem) obj) == 0;
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  private final class MapKey
      extends AbstractMapKey
      implements IOpaqueMapKey {
    @Override
    public IDayTimeDurationItem getKey() {
      return DayTimeDurationItemImpl.this;
    }
  }
}
