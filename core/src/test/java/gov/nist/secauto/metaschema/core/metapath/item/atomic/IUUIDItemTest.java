/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item.atomic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.UUID;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

class IUuidItemTest {
  private static Stream<Arguments> testCompare() { // NOPMD - false positive
    UUID uuidRandom = UUID.randomUUID();
    UUID uuid1 = UUID.fromString("4cfa2c52-9345-4012-8055-0bc9ac9b03fa");
    UUID uuid2 = UUID.fromString("25a6d916-f179-4550-ad2b-7e7cd9df35d2");
    String uuid2String = uuid2.toString();

    return Stream.of(
        Arguments.of(IUuidItem.valueOf(uuidRandom), IUuidItem.valueOf(uuidRandom), IIntegerItem.ZERO),
        Arguments.of(IUuidItem.valueOf(uuid1), IUuidItem.valueOf(uuid2), IIntegerItem.valueOf(2)),
        Arguments.of(IUuidItem.valueOf(uuid2), IStringItem.valueOf(uuid2String), IIntegerItem.ZERO),
        Arguments.of(IStringItem.valueOf(uuid2String), IUuidItem.valueOf(uuid2), IIntegerItem.ZERO));
  }

  @ParameterizedTest
  @MethodSource
  void testCompare(@NonNull IAnyAtomicItem left, @NonNull IAnyAtomicItem right, @NonNull IIntegerItem expectedResult) {
    IIntegerItem result = IIntegerItem.valueOf(left.compareTo(right));
    assertEquals(expectedResult, result);
  }

}
