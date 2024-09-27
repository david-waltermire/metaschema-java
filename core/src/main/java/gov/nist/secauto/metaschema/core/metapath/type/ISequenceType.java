/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.type.impl.SequenceTypeImpl;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface ISequenceType {
  @NonNull
  ISequenceType EMPTY = new ISequenceType() {
    @Override
    public boolean isEmpty() {
      return true;
    }

    @Override
    public Class<? extends IItem> getType() {
      return null;
    }

    @Override
    public Occurrence getOccurrence() {
      return Occurrence.ZERO;
    }

    @Override
    public String toSignature() {
      return "()";
    }

    @Override
    public boolean matches(ICollectionValue item) {
      return false;
    }
  };

  /**
   * Create new sequence type using the provide type and occurrence.
   *
   * @param type
   *          the sequence item type
   * @param occurrence
   *          the expected occurrence of the sequence
   * @return the new sequence type
   */
  @SuppressWarnings("PMD.ShortMethodName")
  @NonNull
  static ISequenceType of(@NonNull Class<? extends IItem> type, @NonNull Occurrence occurrence) {
    return Occurrence.ZERO.equals(occurrence)
        ? EMPTY
        : new SequenceTypeImpl(type, occurrence);
  }

  /**
   * Determine if the sequence is empty (if it holds any data) or not.
   *
   * @return {@code true} if the sequence is empty or {@code false} otherwise
   */
  boolean isEmpty();

  /**
   * Get the type of the sequence.
   *
   * @return the type of the sequence or {@code null} if the sequence is empty
   */
  Class<? extends IItem> getType();

  /**
   * Get the occurrence of the sequence.
   *
   * @return the occurrence of the sequence or {@code Occurrence#ZERO} if the
   *         sequence is empty
   */
  Occurrence getOccurrence();

  /**
   * Get the signature of the function as a string.
   *
   * @return the signature
   */
  @NonNull
  String toSignature();

  boolean matches(@NonNull ICollectionValue item);
}
