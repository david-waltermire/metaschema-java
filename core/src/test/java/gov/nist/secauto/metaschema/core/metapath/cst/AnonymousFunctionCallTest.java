/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import static gov.nist.secauto.metaschema.core.metapath.TestUtils.eqname;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression.ResultType;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.testing.model.mocking.MockedDocumentGenerator;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for anonymous function calls in Metapath expressions.
 * <p>
 * These tests validate the compilation and execution of anonymous functions as
 * defined in the Metaschema specification.
 */
class AnonymousFunctionCallTest {
  private static final String NS = "http://example.com/ns";

  /**
   * Tests the basic functionality of anonymous function definition and execution.
   * This test validates:
   * <ul>
   * <li>Function definition using the 'let' syntax
   * <li>Function execution with string parameters
   * <li>String concatenation within the function body
   * </ul>
   */
  @Test
  void test() {
    StaticContext staticContext = StaticContext.builder()
        .namespace("ex", NS)
        .build();
    DynamicContext dynamicContext = new DynamicContext(staticContext);

    String metapath = "let $function := function($str) as meta:string { fn:concat('extra ',$str) } "
        + "return $function('cool')";

    assertEquals(
        "extra cool",
        IMetapathExpression.compile(metapath, staticContext).evaluateAs(
            null,
            IMetapathExpression.ResultType.STRING,
            dynamicContext));
  }

  @Test
  void testMultipleParameters() {
    StaticContext staticContext = StaticContext.builder()
        .namespace("ex", NS)
        .build();
    DynamicContext dynamicContext = new DynamicContext(staticContext);
    String metapath = "function ($argument1 as meta:string, $argument2 as meta:string) as meta:string { $argument2 }";
    dynamicContext.bindVariableValue(eqname(NS, "boom"),
        IMetapathExpression.compile(metapath, staticContext).evaluate(null, dynamicContext));
    String result = IMetapathExpression.compile("$ex:boom('a', 'b')", staticContext).evaluateAs(null, ResultType.STRING,
        dynamicContext);
    assertEquals(result, "b");
  }

  @Test
  void testDifferentReturnTypes() {
    // FIXME: Add test for functions returning different types
  }

  @Test
  void testErrorCases() {
    // FIXME: Add test for invalid function definitions
  }

  /**
   * This tests for a regression of the issue <a href=
   * "https://github.com/metaschema-framework/metaschema-java/issues/323">metaschema-framework/metaschema-java#323</a>.
   */
  @Test
  void testFunctionParameterUsingFlagNodeArgument() {
    StaticContext staticContext = StaticContext.builder()
        .namespace("ex", NS)
        .defaultModelNamespace(NS)
        .build();
    INodeItem flag = MockedDocumentGenerator.generateOrphanedFlagNodeItem();
    DynamicContext dynamicContext = new DynamicContext(staticContext);
    dynamicContext.bindVariableValue(
        eqname(NS, "should-dereference-param-flag-value"),
        IMetapathExpression
            .compile("function($arg as meta:string) as meta:string { $arg }", dynamicContext.getStaticContext())
            .evaluate(flag, dynamicContext));
    String result
        = IMetapathExpression.compile("$ex:should-dereference-param-flag-value(.)", dynamicContext.getStaticContext())
            .evaluateAs(flag, ResultType.STRING, dynamicContext);
    assertEquals(result, "flag");
  }
}
