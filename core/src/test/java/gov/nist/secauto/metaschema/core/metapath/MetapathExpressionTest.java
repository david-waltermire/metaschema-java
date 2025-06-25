/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.antlr.v4.runtime.misc.ParseCancellationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.hosuaby.inject.resources.junit.jupiter.GivenTextResource;
import io.hosuaby.inject.resources.junit.jupiter.TestWithResources;

@TestWithResources
class MetapathExpressionTest {

  @GivenTextResource(from = "/correct-examples.txt", charset = "UTF-8")
  String correctMetapathInstances;

  // @GivenTextResource(from = "/incorrect-examples.txt", charset = "UTF-8")
  // String incorrectMetapathInstances;

  @ParameterizedTest
  @CsvFileSource(resources = "/correct-examples.txt", delimiter = ';')
  void testCorrect(String line) {
    String parsedLine = line;

    if (parsedLine != null && !parsedLine.startsWith("# ")
        && !parsedLine.contains("text()")
        && !parsedLine.contains("number(")
        && !parsedLine.contains("current(")
        && !parsedLine.contains("last(")) {
      if (parsedLine.endsWith(";")) {
        parsedLine = ObjectUtils.notNull(parsedLine.substring(0, parsedLine.length() - 1));
      }
      // System.out.println(line);
      IMetapathExpression.compile(parsedLine);
    }
  }
  //
  // @Test
  // @Disabled
  // void testIncorrect() {
  // for (String line : incorrectMetapathInstances.split("\\r?\\n")) {
  // if (line.startsWith("# ")) {
  // continue;
  // }
  // // System.out.println(line);
  // try {
  // MetapathExpression.compile(line);
  // } catch (ParseCancellationException ex) {
  // // ex.printStackTrace();
  // }
  // }
  // }

  @Test
  void testSyntaxError() {
    assertThrows(MetapathException.class, () -> {
      IMetapathExpression.compile("**");
    });
  }

  @Test
  void test() {
    IMetapathExpression path = IMetapathExpression.compile("2 eq 1 + 1");
    ISequence<?> result = path.evaluate();
    assertNotNull(result, "null result");
    assertTrue(!result.isEmpty(), "result was empty");
    assertEquals(1, result.size(), "unexpected size");
    assertEquals(true, ((IBooleanItem) result.iterator().next()).toBoolean(), "unexpected result");
  }

  @Test
  void testMalformedIf() {
    InvalidMetapathGrammarException thrown = assertThrows(InvalidMetapathGrammarException.class, () -> {
      IMetapathExpression.compile("if 'a' = '1.1.2' then true() else false()");
    });
    assertThat(thrown)
        .isExactlyInstanceOf(InvalidMetapathGrammarException.class)
        .cause()
        .isExactlyInstanceOf(ParseCancellationException.class);
  }
}
