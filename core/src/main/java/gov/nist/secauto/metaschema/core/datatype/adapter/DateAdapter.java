/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.adapter;

import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatTypes;

import gov.nist.secauto.metaschema.core.datatype.AbstractCustomJavaDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.object.AmbiguousDate;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateItem;
import gov.nist.secauto.metaschema.core.qname.EQNameFactory;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Support for the Metaschema <a href=
 * "https://pages.nist.gov/metaschema/specification/datatypes/#date">date</a>
 * data type.
 */
public class DateAdapter
    extends AbstractCustomJavaDataTypeAdapter<AmbiguousDate, IDateItem> {
  @NonNull
  private static final List<IEnhancedQName> NAMES = ObjectUtils.notNull(
      List.of(
          EQNameFactory.instance().newQName(MetapathConstants.NS_METAPATH, "date")));
  /**
   * Provides a coarse means to parse the date from the timezone. Java handles
   * parsing the rest and raising any temporal errors.
   */
  @NonNull
  private static final Pattern DATE_TIMEZONE = ObjectUtils.notNull(
      Pattern.compile("^(-?[0-9]{4}-[0-9]{2}-[0-9]{2})"
          + "(Z|[+-][0-9]{2}:[0-9]{2})?$"));

  DateAdapter() {
    super(AmbiguousDate.class, IDateItem.class, IDateItem::cast);
  }

  @Override
  public List<IEnhancedQName> getNames() {
    return NAMES;
  }

  @Override
  public JsonFormatTypes getJsonRawType() {
    return JsonFormatTypes.STRING;
  }

  @Override
  public AmbiguousDate parse(String value) {
    Matcher matcher = DATE_TIMEZONE.matcher(value);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Invalid date: " + value);
    }

    String parseValue
        = String.format("%sT00:00:00%s", matcher.group(1), matcher.group(2) == null ? "" : matcher.group(2));
    try {
      TemporalAccessor accessor = DateFormats.DATE_TIME_WITH_TZ.parse(parseValue);
      return new AmbiguousDate(ObjectUtils.notNull(ZonedDateTime.from(accessor)), true); // NOPMD - readability
    } catch (DateTimeParseException ex) {
      try {
        TemporalAccessor accessor = DateFormats.DATE_TIME_WITH_OPTIONAL_TZ.parse(parseValue);
        LocalDate date = LocalDate.from(accessor);
        return new AmbiguousDate(ObjectUtils.notNull(ZonedDateTime.of(date, LocalTime.MIN, ZoneOffset.UTC)), false);
      } catch (DateTimeParseException ex2) {
        IllegalArgumentException newEx = new IllegalArgumentException(ex2.getLocalizedMessage(), ex2);
        newEx.addSuppressed(ex);
        throw newEx;
      }
    }
  }

  @Override
  public String asString(Object obj) {
    AmbiguousDate value = toValue(obj);
    return ObjectUtils.notNull(value.hasTimeZone()
        ? DateFormats.DATE_WITH_TZ.format(value.getValue())
        : DateFormats.DATE_WITH_OPTIONAL_TZ.format(value.getValue()));
  }

  @Override
  public IDateItem newItem(Object value) {
    AmbiguousDate item = toValue(value);
    return IDateItem.valueOf(item);
  }
}
