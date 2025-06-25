/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Declares the expected type information for a {@link IMapItem}.
 */
public interface IMapTest extends IItemType {
  @SuppressWarnings({ "rawtypes" })
  @Override
  default Class<? extends IMapItem> getItemClass() {
    return IMapItem.class;
  }

  /**
   * Get the expected atomic type of the map's key.
   *
   * @return the atomic type
   */
  @NonNull
  IAtomicOrUnionType<?> getKeyType();

  /**
   * Get the sequence test to use to check the map's contents.
   *
   * @return the sequence type
   */
  @NonNull
  ISequenceType getValueType();

  @Override
  default boolean isInstance(IItem item) {
    boolean retval = getItemClass().isInstance(item);
    if (retval) {
      // this is an array
      IMapItem<?> map = (IMapItem<?>) item;

      IAtomicOrUnionType<?> keyType = getKeyType();
      ISequenceType valueType = getValueType();
      retval = map.entrySet().stream()
          .allMatch(entry -> {
            boolean result = keyType.isInstance(entry.getKey().getKey());
            if (result) {
              result = valueType.matches(entry.getValue().toSequence());
            }
            return result;
          });
    }
    return retval;
  }
}
