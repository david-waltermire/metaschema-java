/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function;

import gov.nist.secauto.metaschema.core.metapath.IErrorCode;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * FORG: Exceptions related to argument types.
 */
@SuppressWarnings("PMD.DataClass")
public class InvalidArgumentFunctionException
    extends FunctionMetapathError {
  @NonNull
  private static final String PREFIX = "FORG";

  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0001">err:FORG0001</a>: A
   * general-purpose error raised when casting, if a cast between two datatypes is
   * allowed in principle, but the supplied value cannot be converted: for example
   * when attempting to cast the string "nine" to an integer.
   */
  public static final int INVALID_VALUE_FOR_CAST = 1;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0002">err:FORG0002</a>:
   * Raised when either argument to fn:resolve-uri is not a valid URI/IRI.
   */
  public static final int INVALID_ARGUMENT_TO_RESOLVE_URI = 2;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0003">err:FORG0003</a>:
   * Raised by <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-zero-or-one">fn:zero-or-one</a>
   * if the supplied value contains more than one item.
   *
   */
  public static final int INVALID_ARGUMENT_ZERO_OR_ONE = 3;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0004">err:FORG0005</a>:
   * Raised by <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-one-or-more">fn:one-or-more</a>
   * if the supplied value is an empty sequence.
   */
  public static final int INVALID_ARGUMENT_ONE_OR_MORE = 4;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0005">err:FORG0005</a>:
   * Raised by <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-exactly-one">fn:exactly-one</a>
   * if the supplied value is not a singleton sequence.
   *
   */
  public static final int INVALID_ARGUMENT_EXACTLY_ONE = 5;
  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0006">err:FORG0006</a>:
   * Raised by functions such as
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-max">fn:max</a>,
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-min">fn:min</a>,
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-avg">fn:avg</a>,
   * <a href="https://www.w3.org/TR/xpath-functions-31/#func-sum">fn:sum</a> if
   * the supplied sequence contains values inappropriate to this function.
   */
  public static final int INVALID_ARGUMENT_TYPE = 6;

  /**
   * <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#ERRFORG0008">err:FORG0008</a>:
   * Raised by <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-dateTime">fn:dateTime</a> if
   * the two arguments both have timezones and the timezones are different.
   */
  public static final int DATE_TIME_INCONSISTENT_TIMEZONE = 8;

  /**
   * the serial version UUID.
   */
  private static final long serialVersionUID = 1L;

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
  public InvalidArgumentFunctionException(int code, String message, Throwable cause) {
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
  public InvalidArgumentFunctionException(int code, String message) {
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
  public InvalidArgumentFunctionException(int code, Throwable cause) {
    super(IErrorCode.of(PREFIX, code), cause);
  }
}
