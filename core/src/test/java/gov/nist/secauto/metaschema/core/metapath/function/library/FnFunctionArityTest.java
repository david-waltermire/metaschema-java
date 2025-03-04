/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import static gov.nist.secauto.metaschema.core.metapath.TestUtils.integer;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.metaschema.core.metapath.ExpressionTestBase;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression.ResultType;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

class FnFunctionArityTest
    extends ExpressionTestBase {

  private static Stream<Arguments> provideValues() { // NOPMD - false positive
    return Stream.of(
        Arguments.of(
            integer(2),
            "fn:function-arity(fn:substring#2)"),
        Arguments.of(
            integer(1),
            "fn:function-arity(function($node){name($node)})"));
  }

  @ParameterizedTest
  @MethodSource("provideValues")
  void test(@NonNull IItem expected, @NonNull String metapath) {
    assertEquals(expected,
        IMetapathExpression.compile(metapath).evaluateAs(null, ResultType.ITEM, newDynamicContext()));
  }
}
