/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.AbstractCodedMetapathException;

/**
 * MPTY: Exceptions related to Metapath type errors.
 */
public class TypeMetapathException
    extends AbstractCodedMetapathException {
  /**
   * <a href= "https://www.w3.org/TR/xpath-31/#ERRXPTY0004">err:MPTY0004</a>: It
   * is a <a href="https://www.w3.org/TR/xpath-31/#dt-type-error">type error</a>
   * if during the
   * <a href="https://www.w3.org/TR/xpath-31/#dt-static-analysis">static analysis
   * phase</a>, an expression is found to have a
   * <a href="https://www.w3.org/TR/xpath-31/#dt-static-type">static type</a> that
   * is not appropriate for the context in which the expression occurs, or during
   * the <a href="https://www.w3.org/TR/xpath-31/#dt-dynamic-evaluation">dynamic
   * evaluation phase</a>, the
   * <a href="https://www.w3.org/TR/xpath-31/#dt-dynamic-type">dynamic type</a> of
   * a value does not match a required type as specified by the matching rules in
   * <a href="https://www.w3.org/TR/xpath-31/#id-sequencetype-matching">2.5.5
   * SequenceType Matching</a>.
   */
  public static final int INVALID_TYPE_ERROR = 4;
  /**
   * <a href= "https://www.w3.org/TR/xpath-31/#ERRXPTY0019">err:MPTY0019</a>: It
   * is a <a href="https://www.w3.org/TR/xpath-31/#dt-type-error">type error</a>
   * if {@code E1} in a path expression {@code E1/E2} does not evaluate to a
   * sequence of nodes.
   */
  public static final int BASE_PATH_NOT_A_SEQUENCE = 19;
  /**
   * The context item is not a node when evaluating an axis step.
   */
  public static final int NOT_A_NODE_ITEM_FOR_STEP = 20;

  /**
   * the serial version UID.
   */
  private static final long serialVersionUID = 2L;

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
  public TypeMetapathException(int code, String message, Throwable cause) {
    super(code, message, cause);
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
  public TypeMetapathException(int code, String message) {
    super(code, message);
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
  public TypeMetapathException(int code, Throwable cause) {
    super(code, cause);
  }

  @Override
  public String getCodePrefix() {
    return "MPTY";
  }
}
