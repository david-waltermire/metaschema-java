/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import static gov.nist.secauto.metaschema.core.metapath.TestUtils.integer;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gov.nist.secauto.metaschema.core.metapath.type.InvalidTypeMetapathException;

import org.junit.jupiter.api.Test;

class ISequenceTest {

  @Test
  void testGetFirstNonSingleton() {
    assertAll(
        () -> assertEquals(integer(1), ISequence.of(integer(1), integer(2)).getFirstItem(false)),
        () -> assertEquals(integer(3), ISequence.of(integer(3)).getFirstItem(false)),
        () -> assertNull(ISequence.of().getFirstItem(false)));
  }

  @Test
  void testGetFirstSingleton() {
    assertAll(
        () -> assertThrows(InvalidTypeMetapathException.class,
            () -> ISequence.of(integer(1), integer(2)).getFirstItem(true)),
        () -> assertEquals(integer(3), ISequence.of(integer(3)).getFirstItem(true)),
        () -> assertNull(ISequence.of().getFirstItem(true)));
  }
}
