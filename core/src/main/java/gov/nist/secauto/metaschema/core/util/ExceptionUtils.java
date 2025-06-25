/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.util;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides a means for throwing important checked exceptions over non-checked
 * methods, e.g. lambda invocations.
 * <p>
 * This capability should be used with care, and generally in limited
 * circumstances.
 */
public final class ExceptionUtils {
  @NonNull
  public static WrappedException wrap(@NonNull Throwable ex) {
    return new WrappedException(ex);
  }

  @NonNull
  public static WrappedException wrapAndThrow(@NonNull Throwable ex) {
    return new WrappedException(ex);
  }

  @NonNull
  public static Throwable unwrap(
      @NonNull WrappedException ex) {
    return ex.unwrap();
  }

  @NonNull
  public static <E extends Throwable> E unwrap(
      @NonNull WrappedException ex,
      @NonNull Class<E> wrappedExceptionClass) {
    return ex.unwrap(wrappedExceptionClass);
  }

  /**
   * Supports wrapping a check exception as a runtime exception.
   * <p>
   * The cause of this exception is immutable.
   */
  public static final class WrappedException
      extends RuntimeException {

    /**
     * the serial version UID.
     */
    private static final long serialVersionUID = 2L;

    private WrappedException(@NonNull Throwable cause) {
      super(cause);
    }

    @Override
    public Throwable initCause(Throwable cause) {
      throw new UnsupportedOperationException("must set cause in constructor");
    }

    @NonNull
    public Throwable unwrap() {
      return ObjectUtils.notNull(getCause());
    }

    @NonNull
    public <E extends Throwable> E unwrap(@NonNull Class<E> wrappedExceptionClass) {
      Throwable cause = unwrap();
      if (wrappedExceptionClass.isInstance(cause)) {
        E unwrappedEx = wrappedExceptionClass.cast(cause);
        unwrappedEx.addSuppressed(this);
        return unwrappedEx;
      }
      throw new IllegalArgumentException(
          String.format("Wrapped exception '%s' did not match excpeted type '%s'.",
              cause.getClass().getName(),
              wrappedExceptionClass.getName()));
    }

    public void unwrapAndThrow() throws Throwable {
      throw unwrap();
    }

    public <E extends Throwable> void unwrapAndThrow(@NonNull Class<E> wrappedExceptionClass) throws E {
      throw unwrap(wrappedExceptionClass);
    }
  }

  private ExceptionUtils() {
    // prevent construction
  }
}
