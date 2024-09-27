/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item;

import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IItemWriter {
  /**
   * Write the provided sequence instance.
   *
   * @param sequence
   *          the instance to write
   */
  void writeSequence(@NonNull ISequence<?> sequence);

  /**
   * Write the provided array item instance.
   *
   * @param array
   *          the instance to write
   */
  void writeArray(@NonNull IArrayItem<?> array);

  /**
   * Write the provided map item instance.
   *
   * @param map
   *          the instance to write
   */
  void writeMap(@NonNull IMapItem<?> map);

  /**
   * Write the provided node item instance.
   *
   * @param node
   *          the instance to write
   */
  void writeNode(@NonNull INodeItem node);

  /**
   * Write the provided atomic item instance.
   *
   * @param item
   *          the instance to write
   */
  void writeAtomicValue(@NonNull IAnyAtomicItem item);

  /**
   * Write the provided function item instance.
   *
   * @param function
   *          the instance to write
   */
  void writeFunction(@NonNull IFunction function);
}
