/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function;

import gov.nist.secauto.metaschema.core.metapath.type.ISequenceType;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;

class ArgumentImpl implements IArgument {
  @NonNull
  private final String name;
  @NonNull
  private final ISequenceType sequenceType;

  protected ArgumentImpl(@NonNull String name, @NonNull ISequenceType sequenceType) {
    this.name = name;
    this.sequenceType = sequenceType;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public ISequenceType getSequenceType() {
    return sequenceType;
  }

  @SuppressWarnings("null")
  @Override
  public String toSignature() {
    StringBuilder builder = new StringBuilder();

    // name
    builder.append(getName())
        .append(" as ")
        .append(getSequenceType().toSignature());

    return builder.toString();
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, sequenceType);
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
    ArgumentImpl other = (ArgumentImpl) obj;
    return Objects.equals(name, other.name) && Objects.equals(sequenceType, other.sequenceType);
  }
}
