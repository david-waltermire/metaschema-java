/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.adapter.YearMonthAdapter;
import gov.nist.secauto.metaschema.core.metapath.impl.AbstractMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IYearMonthDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.IOpaqueMapKey;

import java.time.Period;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of a Metapath atomic item containing a duration data value
 * in years and months.
 */
public class YearMonthDurationItemImpl
    extends AbstractDurationItem<Period>
    implements IYearMonthDurationItem {

  /**
   * Construct a new item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  public YearMonthDurationItemImpl(@NonNull Period value) {
    super(value);
  }

  @Override
  public Period asPeriod() {
    return getValue();
  }

  @Override
  public YearMonthAdapter getJavaTypeAdapter() {
    return MetaschemaDataTypeProvider.YEAR_MONTH_DURATION;
  }

  @Override
  public int hashCode() {
    return Objects.hash(asPeriod());
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IYearMonthDurationItem && compareTo((IYearMonthDurationItem) obj) == 0;
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  private final class MapKey
      extends AbstractMapKey
      implements IOpaqueMapKey {
    @Override
    public IYearMonthDurationItem getKey() {
      return YearMonthDurationItemImpl.this;
    }
  }
}
