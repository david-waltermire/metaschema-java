/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic.impl;

import gov.nist.secauto.metaschema.core.metapath.item.atomic.AbstractAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapKey;
import gov.nist.secauto.metaschema.core.metapath.item.function.impl.AbstractStringMapKey;

import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A common base class for all items derived from {@link IStringItem}.
 */
public abstract class AbstractStringItem
    extends AbstractAnyAtomicItem<String>
    implements IStringItem {
  private static final String WHITESPACE_SEGMENT = "[ \t\r\n]";
  /**
   * Pattern to match one or more whitespace characters at the end of a string.
   */
  private static final Pattern TRIM_END = Pattern.compile(WHITESPACE_SEGMENT + "++$");
  /**
   * Pattern to match one or more whitespace characters at the start of a string.
   */
  private static final Pattern TRIM_START = Pattern.compile("^" + WHITESPACE_SEGMENT + "+");
  /**
   * Pattern to match two or more consecutive whitespace characters.
   */
  private static final Pattern TRIM_MIDDLE = Pattern.compile(WHITESPACE_SEGMENT + "{2,}");

  /**
   * Construct a new string item with the provided {@code value}.
   *
   * @param value
   *          the value to wrap
   */
  protected AbstractStringItem(@NonNull String value) {
    super(value);
  }

  @Override
  public String asString() {
    return getValue();
  }

  @Override
  public IMapKey asMapKey() {
    return new MapKey();
  }

  @Override
  public IStringItem normalizeSpace() {
    String value = asString();
    value = TRIM_START.matcher(value).replaceFirst("");
    value = TRIM_MIDDLE.matcher(value).replaceAll(" ");
    value = TRIM_END.matcher(value).replaceFirst("");
    assert value != null;

    return IStringItem.valueOf(value);
  }

  @Override
  protected String getValueSignature() {
    return "'" + getValue() + "'";
  }

  @Override
  public int hashCode() {
    return asString().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || obj instanceof IStringItem && compareTo((IStringItem) obj) == 0;
  }

  private final class MapKey
      extends AbstractStringMapKey {

    @Override
    public IStringItem getKey() {
      return AbstractStringItem.this;
    }

    @Override
    public String asString() {
      return getKey().asString();
    }
  }

}
