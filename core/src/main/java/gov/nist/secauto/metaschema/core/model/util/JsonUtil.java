/*
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

package gov.nist.secauto.metaschema.core.model.util;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public final class JsonUtil {
  private static final Logger LOGGER = LogManager.getLogger(JsonUtil.class);

  private JsonUtil() {
    // disable construction
  }

  /**
   * Parse the input stream into a JSON object.
   *
   * @param is
   *          the input stream to parse
   * @return the JSON object
   */
  @NonNull
  public static JSONObject toJsonObject(@NonNull InputStream is) {
    return new JSONObject(new JSONTokener(is));
  }

  /**
   * Parse the reader into a JSON object.
   *
   * @param reader
   *          the reader to parse
   * @return the JSON object
   */
  @NonNull
  public static JSONObject toJsonObject(@NonNull Reader reader) {
    return new JSONObject(new JSONTokener(reader));
  }

  /**
   * Generate an informational string describing the token at the current location
   * of the provided {@code parser}.
   *
   * @param parser
   *          the JSON parser
   * @return the informational string
   * @throws IOException
   *           if an error occurred while getting the information from the parser
   */
  @SuppressWarnings("null")
  @NonNull
  public static String toString(@NonNull JsonParser parser) throws IOException {
    return new StringBuilder(32)
        .append(parser.currentToken().name())
        .append(" '")
        .append(parser.getText())
        .append('\'')
        .append(generateLocationMessage(parser))
        .toString();
  }

  /**
   * Generate an informational string describing the provided {@code location}.
   *
   * @param location
   *          a JSON parser location
   * @return the informational string
   */
  @SuppressWarnings("null")
  @NonNull
  public static String toString(@NonNull JsonLocation location) {
    return new StringBuilder(8)
        .append(location.getLineNr())
        .append(':')
        .append(location.getColumnNr())
        .toString();
  }

  /**
   * Advance the parser to the next location matching the provided token.
   *
   * @param parser
   *          the JSON parser
   * @param token
   *          the expected token
   * @return the current token or {@code null} if no tokens remain in the stream
   * @throws IOException
   *           if an error occurred while parsing the JSON
   */
  @Nullable
  public static JsonToken advanceTo(@NonNull JsonParser parser, @NonNull JsonToken token) throws IOException {
    JsonToken currentToken = null;
    while (parser.hasCurrentToken() && !token.equals(currentToken = parser.currentToken())) {
      currentToken = parser.nextToken();
      if (LOGGER.isWarnEnabled()) {
        LOGGER.warn("skipping over: {}{}",
            toString(parser),
            generateLocationMessage(parser));
      }
    }
    return currentToken;
  }

  /**
   * Skip the next JSON value in the stream.
   *
   * @param parser
   *          the JSON parser
   * @return the current token or {@code null} if no tokens remain in the stream
   * @throws IOException
   *           if an error occurred while parsing the JSON
   */
  @SuppressWarnings({
      "resource", // parser not owned
      "PMD.CyclomaticComplexity" // acceptable
  })
  @Nullable
  public static JsonToken skipNextValue(@NonNull JsonParser parser) throws IOException {

    JsonToken currentToken = parser.currentToken();
    // skip the field name
    if (JsonToken.FIELD_NAME.equals(currentToken)) {
      currentToken = parser.nextToken();
    }

    switch (currentToken) {
    case START_ARRAY:
    case START_OBJECT:
      parser.skipChildren();
      break;
    case VALUE_FALSE:
    case VALUE_NULL:
    case VALUE_NUMBER_FLOAT:
    case VALUE_NUMBER_INT:
    case VALUE_STRING:
    case VALUE_TRUE:
      // do nothing
      break;
    default:
      // error
      String msg = String.format("Unhandled JsonToken %s%s.",
          toString(parser),
          generateLocationMessage(parser));
      LOGGER.error(msg);
      throw new UnsupportedOperationException(msg);
    }

    // advance past the value
    return parser.nextToken();
  }
  //
  // @SuppressWarnings("PMD.CyclomaticComplexity") // acceptable
  // private static boolean checkEndOfValue(@NonNull JsonParser parser, @NonNull
  // JsonToken startToken) {
  // JsonToken currentToken = parser.getCurrentToken();
  //
  // boolean retval;
  // switch (startToken) { // NOPMD - intentional fall through
  // case START_OBJECT:
  // retval = JsonToken.END_OBJECT.equals(currentToken);
  // break;
  // case START_ARRAY:
  // retval = JsonToken.END_ARRAY.equals(currentToken);
  // break;
  // case VALUE_EMBEDDED_OBJECT:
  // case VALUE_FALSE:
  // case VALUE_NULL:
  // case VALUE_NUMBER_FLOAT:
  // case VALUE_NUMBER_INT:
  // case VALUE_STRING:
  // case VALUE_TRUE:
  // retval = true;
  // break;
  // default:
  // retval = false;
  // }
  // return retval;
  // }

  /**
   * Ensure that the current token is one of the provided tokens.
   * <p>
   * Note: This uses a Java assertion to support debugging in a whay that doesn't
   * impact parser performance during production operation.
   *
   * @param parser
   *          the JSON parser
   * @param expectedTokens
   *          the tokens for which one is expected to match against the current
   *          token
   */
  public static void assertCurrent(
      @NonNull JsonParser parser,
      @NonNull JsonToken... expectedTokens) {
    JsonToken current = parser.currentToken();
    assert Arrays.stream(expectedTokens)
        .anyMatch(expected -> expected.equals(current)) : generateExpectedMessage(
            parser,
            expectedTokens,
            parser.currentToken());
  }

  // public static void assertCurrentIsFieldValue(@NonNull JsonParser parser) {
  // JsonToken token = parser.currentToken();
  // assert token.isStructStart() || token.isScalarValue() : String.format(
  // "Expected a START_OBJECT, START_ARRAY, or VALUE_xxx token, but found
  // JsonToken '%s'%s.",
  // token,
  // generateLocationMessage(parser));
  // }

  /**
   * Ensure that the current token is the one expected and then advance the token
   * stream.
   *
   * @param parser
   *          the JSON parser
   * @param expectedToken
   *          the expected token
   * @return the next token
   * @throws IOException
   *           if an error occurred while reading the token stream
   */
  @Nullable
  public static JsonToken assertAndAdvance(
      @NonNull JsonParser parser,
      @NonNull JsonToken expectedToken)
      throws IOException {
    JsonToken token = parser.currentToken();
    assert expectedToken.equals(token) : generateExpectedMessage(
        parser,
        expectedToken,
        token);
    return parser.nextToken();
  }

  /**
   * Advance the token stream, then ensure that the current token is the one
   * expected.
   *
   * @param parser
   *          the JSON parser
   * @param expectedToken
   *          the expected token
   * @return the next token
   * @throws IOException
   *           if an error occurred while reading the token stream
   */
  @Nullable
  public static JsonToken advanceAndAssert(
      @NonNull JsonParser parser,
      @NonNull JsonToken expectedToken)
      throws IOException {
    JsonToken token = parser.nextToken();
    assert expectedToken.equals(token) : generateExpectedMessage(
        parser,
        expectedToken,
        token);
    return token;
  }

  /**
   * Generate a message intended for error reporting based on a presumed token.
   *
   * @param parser
   *          the JSON parser
   * @param expectedToken
   *          the expected token
   * @param actualToken
   *          the actual token found
   * @return the message string
   */
  @NonNull
  private static String generateExpectedMessage(
      @NonNull JsonParser parser,
      @NonNull JsonToken expectedToken,
      JsonToken actualToken) {
    return ObjectUtils.notNull(
        String.format("Expected JsonToken '%s', but found JsonToken '%s'%s.",
            expectedToken,
            actualToken,
            generateLocationMessage(parser)));
  }

  /**
   * Generate a message intended for error reporting based on a presumed set of
   * tokens.
   *
   * @param parser
   *          the JSON parser
   * @param expectedTokens
   *          the set of expected tokens, one of which was expected to match the
   *          actual token
   * @param actualToken
   *          the actual token found
   * @return the message string
   */
  @NonNull
  private static String generateExpectedMessage(
      @NonNull JsonParser parser,
      @NonNull JsonToken[] expectedTokens,
      JsonToken actualToken) {
    List<JsonToken> expectedTokensList = ObjectUtils.notNull(Arrays.asList(expectedTokens));
    return generateExpectedMessage(parser, expectedTokensList, actualToken);
  }

  /**
   * Generate a message intended for error reporting based on a presumed set of
   * tokens.
   *
   * @param parser
   *          the JSON parser
   * @param expectedTokens
   *          the set of expected tokens, one of which was expected to match the
   *          actual token
   * @param actualToken
   *          the actual token found
   * @return the message string
   */
  @NonNull
  private static String generateExpectedMessage(
      @NonNull JsonParser parser,
      @NonNull Collection<JsonToken> expectedTokens,
      JsonToken actualToken) {
    return ObjectUtils.notNull(
        String.format("Expected JsonToken(s) '%s', but found JsonToken '%s'%s.",
            expectedTokens.stream().map(Enum::name).collect(CustomCollectors.joiningWithOxfordComma("or")),
            actualToken,
            generateLocationMessage(parser)));
  }

  /**
   * Generate a location string for the current location in the JSON token stream.
   *
   * @param parser
   *          the JSON parser
   * @return the location string
   */
  @NonNull
  public static CharSequence generateLocationMessage(@NonNull JsonParser parser) {
    JsonLocation location = parser.getCurrentLocation();
    return location == null ? "" : generateLocationMessage(location);
  }

  /**
   * Generate a location string for the current location in the JSON token stream.
   *
   * @param location
   *          a JSON token stream location
   * @return the location string
   */
  @SuppressWarnings("null")
  @NonNull
  public static CharSequence generateLocationMessage(@NonNull JsonLocation location) {
    return new StringBuilder()
        .append(" at location '")
        .append(location.getLineNr())
        .append(':')
        .append(location.getColumnNr())
        .append('\'');
  }
}
