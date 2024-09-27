/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Identifies the occurrence of a sequence used a function argument or return
 * value.
 */
public enum Occurrence {
  /**
   * An empty sequence.
   */
  ZERO("", true, Occurrence::handleZero),
  /**
   * The occurrence indicator {@code "?"}.
   */
  ZERO_OR_ONE("?", true, Occurrence::handleZeroOrOne),
  /**
   * No occurrence indicator.
   */
  ONE("", false, Occurrence::handleOne),
  /**
   * The occurrence indicator {@code "*"}.
   */
  ZERO_OR_MORE("*", true, Occurrence::handleZeroOrMore),
  /**
   * The occurrence indicator {@code "+"}.
   */
  ONE_OR_MORE("+", false, Occurrence::handleOneOrMore);

  @NonNull
  private final String indicator;
  private final boolean optional;
  @NonNull
  private final ISequenceHandler sequenceHandler;

  Occurrence(@NonNull String indicator, boolean optional, @NonNull ISequenceHandler sequenceHandler) {
    Objects.requireNonNull(indicator, "indicator");
    this.indicator = indicator;
    this.optional = optional;
    this.sequenceHandler = sequenceHandler;
  }

  /**
   * Get the occurrence indicator to use in the signature string for the argument.
   *
   * @return the occurrence indicator
   */
  @NonNull
  public String getIndicator() {
    return indicator;
  }

  /**
   * Determine if providing a value is optional based on the occurrence.
   *
   * @return {@code true} if providing a value is optional or {@code false} if
   *         required
   */
  public boolean isOptional() {
    return optional;
  }

  /**
   * Get the handler used to check that a sequence meets the occurrence
   * requirement.
   *
   * @return the handler
   */
  @NonNull
  public ISequenceHandler getSequenceHandler() {
    return sequenceHandler;
  }

  @NonNull
  private static <T extends IItem> ISequence<T> handleZero(@NonNull ISequence<T> sequence) {
    int size = sequence.size();
    if (size != 0) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("an empty sequence expected, but size is '%d'", size));
    }
    return ISequence.empty();
  }

  @NonNull
  private static <T extends IItem> ISequence<T> handleOne(@NonNull ISequence<T> sequence) {
    int size = sequence.size();
    if (size != 1) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("a sequence of one expected, but size is '%d'", size));
    }

    T item = sequence.getFirstItem(true);
    return item == null ? ISequence.empty() : ISequence.of(item);
  }

  @NonNull
  private static <T extends IItem> ISequence<T> handleZeroOrOne(@NonNull ISequence<T> sequence) {
    int size = sequence.size();
    if (size > 1) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("a sequence of zero or one expected, but size is '%d'", size));
    }

    T item = sequence.getFirstItem(false);
    return item == null ? ISequence.empty() : ISequence.of(item);
  }

  @NonNull
  private static <T extends IItem> ISequence<T> handleZeroOrMore(@NonNull ISequence<T> sequence) {
    return sequence;
  }

  @NonNull
  private static <T extends IItem> ISequence<T> handleOneOrMore(@NonNull ISequence<T> sequence) {
    int size = sequence.size();
    if (size < 1) {
      throw new InvalidTypeMetapathException(
          null,
          String.format("a sequence of one or more expected, but size is '%d'", size));
    }
    return sequence;
  }

  @FunctionalInterface
  public interface ISequenceHandler {
    /**
     * Check the provided sequence matches the occurrence.
     * <p>
     * This method may return a new sequence that more efficiently addresses the
     * occurrence.
     *
     * @param <T>
     *          the sequence item Java type
     * @param sequence
     *          the sequence to check occurrence for
     * @return the sequence
     * @throws InvalidTypeMetapathException
     *           if the sequence doesn't match the required occurrence
     */
    @NonNull
    <T extends IItem> ISequence<T> handle(@NonNull ISequence<T> sequence);
  }
}
