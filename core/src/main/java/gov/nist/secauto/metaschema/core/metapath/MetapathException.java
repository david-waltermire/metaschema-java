/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * {@code MetapathException} is the superclass of all exceptions that can be
 * thrown during the compilation and evaluation of a Metapath.
 */
public class MetapathException
    extends RuntimeException {
  /**
   * the serial version UID.
   */
  private static final long serialVersionUID = 1L;
  /**
   * The error prefix which identifies what kind of error it is.
   */
  @NonNull
  private final IErrorCode errorCode;

  @Nullable
  private Deque<IExpression> evaluationStack;

  /**
   * Constructs a new Metapath exception with the provided {@code code} and
   * {@code message} and no cause.
   *
   * @param errorCode
   *          the error code that identifies the type of error
   * @param message
   *          the exception message
   */
  protected MetapathException(
      @NonNull IErrorCode errorCode,
      @Nullable String message) {
    super(message);
    this.errorCode = errorCode;
  }

  /**
   * Constructs a new Metapath exception with a {@code null} message and the
   * provided {@code code} and {@code cause}.
   *
   * @param errorCode
   *          the error code that identifies the type of error
   * @param cause
   *          the exception cause
   */
  protected MetapathException(
      @NonNull IErrorCode errorCode,
      @Nullable Throwable cause) {
    super(cause);
    this.errorCode = errorCode;
  }

  /**
   * Constructs a new Metapath exception with the provided {@code code},
   * {@code message} and {@code cause}.
   *
   * @param errorCode
   *          the error code that identifies the type of error
   * @param message
   *          the exception message
   * @param cause
   *          the exception cause
   */
  protected MetapathException(
      @NonNull IErrorCode errorCode,
      @Nullable String message,
      @Nullable Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public MetapathException registerEvaluationContext(@NonNull DynamicContext dynamicContext) {
    if (evaluationStack == null) {
      evaluationStack = dynamicContext.getExecutionStack();
    }
    return this;
  }

  public MetapathException registerEvaluationContext(@NonNull IMetapathExpression metapath) {
    if (evaluationStack == null) {
      evaluationStack = new ArrayDeque<>(Collections.singleton(metapath));
    }
    return this;
  }

  @Nullable
  protected Deque<IExpression> getEvaluationStack() {
    return evaluationStack;
  }

  @Override
  public final String getMessage() {
    String message = getMessageText();
    return String.format(
        "%s%s",
        getErrorCode().toString(),
        message == null ? "" : ": " + message);
  }

  /**
   * Get the message text without the error code prefix.
   *
   * @return the message text or {@code null}
   */
  @Nullable
  public String getMessageText() {
    String msg = super.getMessage();

    Deque<IExpression> stack = getEvaluationStack();

    if (stack != null && !stack.isEmpty()) {
      IExpression head = stack.peekLast();
      msg = String.format(
          "An error occurred while evaluating the expression '%s'%s",
          head.getPath(),
          msg == null ? "" : ": " + msg);
    }
    return msg;
  }

  /**
   * Get the error code, which indicates what type of error it is.
   *
   * @return the error code
   */
  @NonNull
  public final IErrorCode getErrorCode() {
    return errorCode;
  }

}
