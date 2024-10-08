/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import static gov.nist.secauto.metaschema.core.metapath.TestUtils.string;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.metaschema.core.metapath.ExpressionTestBase;
import gov.nist.secauto.metaschema.core.metapath.MetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

class FnSubstringTest
    extends ExpressionTestBase {
  private static Stream<Arguments> provideValues() { // NOPMD - false positive
    return Stream.of(
        Arguments.of(
            string(" car"),
            "substring('motor car', 6)"), // 6, 4
        Arguments.of(
            string("ada"),
            "substring('metadata', 4, 3)"),
        Arguments.of(
            string("234"),
            "substring('12345', 1.5, 2.6)"),
        Arguments.of(
            string("12"),
            "substring('12345', 0, 3)"),
        Arguments.of(
            string(""),
            "substring('12345', 5, -3)"),
        Arguments.of(
            string("1"),
            "substring('12345', -3, 5)"),
        Arguments.of(
            string(""),
            "substring((), 1, 3)")
    // Arguments.of(
    // string(""),
    // "substring('12345', 0 div 0E0, 3)"),
    // Arguments.of(
    // string(""),
    // "substring('12345', 1, 0 div 0E0)"),
    // Arguments.of(
    // string("12345"),
    // "substring('12345', -42, 1 div 0E0)"),
    // Arguments.of(
    // string("12345"),
    // "substring('12345', -1 div 0E0, 1 div 0E0)")
    );
  }

  @ParameterizedTest
  @MethodSource("provideValues")
  void testExpression(@NonNull IStringItem expected, @NonNull String metapath) {
    assertEquals(
        expected,
        MetapathExpression.compile(metapath)
            .evaluateAs(null, MetapathExpression.ResultType.ITEM, newDynamicContext()));
  }

}
