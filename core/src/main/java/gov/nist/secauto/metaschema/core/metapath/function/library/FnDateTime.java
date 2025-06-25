/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.InvalidArgumentFunctionException;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.ITimeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-dateTime">fn:dateTime</a>
 * function.
 */
public final class FnDateTime {
  @NonNull
  private static final String NAME = "dateTime";
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("date")
          .type(IDateItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("time")
          .type(ITimeItem.type())
          .zeroOrOne()
          .build())
      .returnType(IDateTimeItem.type())
      .returnOne()
      .functionHandler(FnDateTime::execute)
      .build();

  private FnDateTime() {
    // disable construction
  }

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IDateTimeItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IDateItem date = IDateItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    ITimeItem time = ITimeItem.type().ofTypeOrNull(arguments.get(1).getFirstItem(true));

    return ISequence.of(fnDateTimeOfNullable(date, time));
  }

  /**
   * Create a date/time item from the provided date and time values.
   * <p>
   * Implements the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-current-date">fn:current-date</a>
   * function.
   *
   * @param date
   *          the date value to get the year, month, and day from or {@code null}
   * @param time
   *          the time value to get the hour, minute, seconds from or {@code null}
   * @return the data/time value composed of the provided date and time values or
   *         {@code null} if either date or time value is {@code null}
   */
  @Nullable
  public static IDateTimeItem fnDateTimeOfNullable(@Nullable IDateItem date, @Nullable ITimeItem time) {
    return date == null || time == null
        ? null
        : fnDateTime(date, time);
  }

  /**
   * Create a date/time item from the provided date and time values.
   * <p>
   * Implements the XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-current-date">fn:current-date</a>
   * function.
   *
   * @param date
   *          the date value to get the year, month, and day from
   * @param time
   *          the time value to get the hour, minute, seconds from
   * @return the data/time value composed of the provided date and time values
   */
  @NonNull
  public static IDateTimeItem fnDateTime(@NonNull IDateItem date, @NonNull ITimeItem time) {
    ZoneId timezone = getTimezone(
        date.hasTimezone() ? date.asZonedDateTime().getZone() : null,
        time.hasTimezone() ? time.asOffsetTime().getOffset().normalized() : null);
    ZonedDateTime dateTime = ObjectUtils.notNull(ZonedDateTime.of(
        date.asLocalDate(),
        time.asLocalTime(),
        timezone == null ? ZoneOffset.UTC : timezone));
    return IDateTimeItem.valueOf(dateTime, timezone != null);
  }

  @Nullable
  private static ZoneId getTimezone(ZoneId dateZoneId, ZoneId timeZoneId) {
    ZoneId retval;
    if (Objects.equals(dateZoneId, timeZoneId) || dateZoneId != null && timeZoneId == null) {
      retval = dateZoneId;
    } else if (dateZoneId == null && timeZoneId != null) {
      retval = timeZoneId;
    } else {
      throw new InvalidArgumentFunctionException(
          InvalidArgumentFunctionException.DATE_TIME_INCONSISTENT_TIMEZONE,
          String.format("The date ('%s') and time ('%s') timezones are inconsistent.",
              dateZoneId == null ? "<none>" : dateZoneId.getId(),
              timeZoneId == null ? "<none>" : timeZoneId.getId()));
    }
    return retval;
  }
}
