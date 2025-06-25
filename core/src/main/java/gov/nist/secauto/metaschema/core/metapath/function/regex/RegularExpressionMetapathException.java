/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.regex;

import gov.nist.secauto.metaschema.core.metapath.IErrorCode;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

@SuppressWarnings("PMD.DataClass")
public class RegularExpressionMetapathException
    extends MetapathException {
  @NonNull
  private static final String PREFIX = "MPRX";
  /**
   * the serial version UID.
   */
  private static final long serialVersionUID = 1L;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORX0001">err:MPRX0001</a>:
   * Raised by regular expression functions such as <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-matches">fn:matches</a> and
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-replace">fn:replace</a> if
   * the regular expression flags contain a character other than i, m, q, s, or x.
   */
  public static final int INVALID_FLAG = 1;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORX0002">err:MPRX0002</a>:
   * Raised by regular expression functions such as <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-matches">fn:matches</a> and
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-replace">fn:replace</a> if
   * the regular expression is syntactically invalid.
   */
  public static final int INVALID_EXPRESSION = 2;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORX0003">err:MPRX0003</a>: For
   * functions such as <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-replace">fn:replace</a> and
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-tokenize">fn:tokenize</a>,
   * raises an error if the supplied regular expression is capable of matching a
   * zero length string.
   */
  public static final int MATCHES_ZERO_LENGTH_STRING = 3;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORX0004">err:MPRX0004</a>:
   * Raised by <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-replace">fn:replace</a> to
   * report errors in the replacement string.
   */
  public static final int INVALID_REPLACEMENT_STRING = 4;

  /**
   * Constructs a new exception with the provided {@code code}, {@code message},
   * and {@code cause}.
   *
   * @param code
   *          the error code value
   * @param message
   *          the exception message
   * @param cause
   *          the original exception cause
   */
  public RegularExpressionMetapathException(
      int code,
      @Nullable String message,
      @Nullable Throwable cause) {
    super(IErrorCode.of(PREFIX, code), message, cause);
  }

  /**
   * Constructs a new exception with the provided {@code code}, {@code message},
   * and no cause.
   *
   * @param code
   *          the error code value
   * @param message
   *          the exception message
   */
  public RegularExpressionMetapathException(
      int code,
      @Nullable String message) {
    super(IErrorCode.of(PREFIX, code), message);
  }

  /**
   * Constructs a new exception with the provided {@code code}, no message, and
   * the {@code cause}.
   *
   * @param code
   *          the error code value
   * @param cause
   *          the original exception cause
   */
  public RegularExpressionMetapathException(
      int code,
      @Nullable Throwable cause) {
    super(IErrorCode.of(PREFIX, code), cause);
  }
}
