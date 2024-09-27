/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import static org.junit.jupiter.api.Assertions.assertEquals;

import gov.nist.secauto.metaschema.core.metapath.EQNameUtils;
import gov.nist.secauto.metaschema.core.metapath.EQNameUtils.PrefixToNamespaceResolver;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

class EQNameUtilsTest {
  private static final StaticContext STATIC_CONTEXT = StaticContext.builder()
      .namespace("prefix", "http://example.com/ns/prefix")
      .defaultFunctionNamespace("http://example.com/ns/function")
      .defaultModelNamespace("http://example.com/ns/model")
      .build();

  static Stream<Arguments> provideValues() {
    return Stream.of(
        Arguments.of(
            "prefix:local-name",
            new QName("http://example.com/ns/prefix", "local-name"),
            STATIC_CONTEXT.getFunctionPrefixResolver()),
        Arguments.of(
            "prefix:local-name",
            new QName("http://example.com/ns/prefix", "local-name"),
            STATIC_CONTEXT.getFlagPrefixResolver()),
        Arguments.of(
            "prefix:local-name",
            new QName("http://example.com/ns/prefix", "local-name"),
            STATIC_CONTEXT.getVariablePrefixResolver()),
        Arguments.of(
            "prefix:local-name",
            new QName("http://example.com/ns/prefix", "local-name"),
            STATIC_CONTEXT.getModelPrefixResolver()),
        Arguments.of(
            "local-name",
            new QName("http://example.com/ns/function", "local-name"),
            STATIC_CONTEXT.getFunctionPrefixResolver()),
        Arguments.of(
            "local-name",
            new QName("local-name"),
            STATIC_CONTEXT.getFlagPrefixResolver()),
        Arguments.of(
            "local-name",
            new QName("local-name"),
            STATIC_CONTEXT.getVariablePrefixResolver()),
        Arguments.of(
            "local-name",
            new QName("http://example.com/ns/model", "local-name"),
            STATIC_CONTEXT.getModelPrefixResolver()),
        Arguments.of("Q{http://example.com/ns}local-name",
            new QName("http://example.com/ns", "local-name"),
            STATIC_CONTEXT.getFunctionPrefixResolver()),
        Arguments.of("Q{http://example.com/ns}local-name",
            new QName("http://example.com/ns", "local-name"),
            STATIC_CONTEXT.getFlagPrefixResolver()),
        Arguments.of("Q{http://example.com/ns}local-name",
            new QName("http://example.com/ns", "local-name"),
            STATIC_CONTEXT.getVariablePrefixResolver()),
        Arguments.of("Q{http://example.com/ns}local-name",
            new QName("http://example.com/ns", "local-name"),
            STATIC_CONTEXT.getModelPrefixResolver()));
  }

  @ParameterizedTest
  @MethodSource("provideValues")
  void test(
      @NonNull String eqname,
      @NonNull QName expected,
      @NonNull PrefixToNamespaceResolver resolver) {

    QName actual = EQNameUtils.parseName(eqname, resolver);
    assertEquals(expected, actual);
  }
}
