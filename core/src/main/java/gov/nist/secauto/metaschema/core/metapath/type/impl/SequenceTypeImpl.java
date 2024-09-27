/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;
import gov.nist.secauto.metaschema.core.metapath.type.Occurrence;
import gov.nist.secauto.metaschema.core.metapath.type.TypeSystem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;

public class SequenceTypeImpl implements ISequenceType {
  private final Class<? extends IItem> type;
  private final Occurrence occurrence;

  public SequenceTypeImpl(@NonNull Class<? extends IItem> type, @NonNull Occurrence occurrence) {
    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(occurrence, "occurrence");
    this.type = type;
    this.occurrence = occurrence;
  }

  @Override
  public boolean isEmpty() {
    return false;
  }

  @Override
  public Class<? extends IItem> getType() {
    return type;
  }

  @Override
  public Occurrence getOccurrence() {
    return occurrence;
  }

  @Override
  public String toString() {
    return toSignature();
  }

  @Override
  public String toSignature() {
    StringBuilder builder = new StringBuilder();

    Class<? extends IItem> type = getType();
    // name
    builder.append(type == null
        ? ""
        : TypeSystem.getName(type))
        // occurrence
        .append(getOccurrence().getIndicator());

    return ObjectUtils.notNull(builder.toString());
  }

  @Override
  public int hashCode() {
    return Objects.hash(occurrence, type);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true; // NOPMD - readability
    }
    if (obj == null) {
      return false; // NOPMD - readability
    }
    if (getClass() != obj.getClass()) {
      return false; // NOPMD - readability
    }
    ISequenceType other = (ISequenceType) obj;
    return Objects.equals(occurrence, other.getOccurrence()) && Objects.equals(type, other.getType());
  }
}
