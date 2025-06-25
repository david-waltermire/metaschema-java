/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public abstract class AbstractItemTypeBase implements IItemType {

  private Lazy<String> signature;
  private Lazy<Integer> hashcode;

  protected AbstractItemTypeBase() {
    this.signature = Lazy.of(this::generateSignature);
    this.hashcode = Lazy.of(this::generateHashCode);
  }

  @NonNull
  protected abstract String generateSignature();

  protected int generateHashCode() {
    return Objects.hash(toSignature());
  }

  @Override
  public String toSignature() {
    return ObjectUtils.notNull(signature.get());
  }

  @Override
  public int hashCode() {
    return hashcode.get();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    AbstractItemTypeBase other = (AbstractItemTypeBase) obj;
    return Objects.equals(toSignature(), other.toSignature());
  }

  @Override
  public String toString() {
    return toSignature();
  }
}
