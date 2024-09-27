/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.function.library.FnData;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.type.TypeMetapathException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public abstract class AbstractExpression implements IExpression {
  /**
   * Get the first data item of the provided {@code sequence} cast to an
   * {@link IAnyAtomicItem}.
   *
   * @param sequence
   *          the sequence to get the data item from
   * @param requireSingleton
   *          if {@code true} then a {@link TypeMetapathException} is thrown if
   *          the sequence contains more than one item
   * @return {@code null} if the sequence is empty, or the item otherwise
   * @throws TypeMetapathException
   *           if the sequence contains more than one item and requireSingleton is
   *           {@code true}, or if the data item cannot be cast
   */
  @Nullable
  public static IAnyAtomicItem getFirstDataItem(@NonNull ISequence<?> sequence,
      boolean requireSingleton) {
    return FnData.fnData(sequence).getFirstItem(requireSingleton);
  }

  @Override
  public String toString() {
    return CSTPrinter.toString(this);
  }
}
