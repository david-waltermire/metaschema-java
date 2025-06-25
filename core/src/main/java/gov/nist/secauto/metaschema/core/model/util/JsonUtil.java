/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
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
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides utility functions to support reading and writing JSON, and for
 * producing error and warning messages.
 */
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
   * @param resource
   *          the resource being parsed
   * @return the informational string
   * @throws IOException
   *           if an error occurred while getting the information from the parser
   */
  @SuppressWarnings("null")
  @NonNull
  public static String toString(
      @NonNull JsonParser parser,
      @NonNull URI resource) throws IOException {
    return new StringBuilder(32)
        .append(parser.currentToken().name())
        .append(" '")
        .append(parser.getText())
        .append('\'')
        .append(generateLocationMessage(parser, resource))
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
   * @param resource
   *          the resource being parsed
   * @param token
   *          the expected token
   * @return the current token or {@code null} if no tokens remain in the stream
   * @throws IOException
   *           if an error occurred while parsing the JSON
   */
  @Nullable
  public static JsonToken advanceTo(
      @NonNull JsonParser parser,
      @NonNull URI resource,
      @NonNull JsonToken token) throws IOException {
    JsonToken currentToken = null;
    while (parser.hasCurrentToken() && !token.equals(currentToken = parser.currentToken())) {
      currentToken = parser.nextToken();
      if (LOGGER.isWarnEnabled()) {
        LOGGER.warn("skipping over: {}",
            toString(parser, resource));
      }
    }
    return currentToken;
  }

  /**
   * Skip the next JSON value in the stream.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
   * @return the current token or {@code null} if no tokens remain in the stream
   * @throws IOException
   *           if an error occurred while parsing the JSON
   */
  @SuppressWarnings({
      "resource", // parser not owned
      "PMD.CyclomaticComplexity" // acceptable
  })
  @Nullable
  public static JsonToken skipNextValue(
      @NonNull JsonParser parser,
      @NonNull URI resource) throws IOException {

    JsonToken currentToken = parser.currentToken();
    // skip the field name
    if (JsonToken.FIELD_NAME.equals(currentToken)) {
      currentToken = parser.nextToken();
    }

    switch (currentToken) {
    case START_ARRAY:
    case START_OBJECT:
    case VALUE_EMBEDDED_OBJECT:
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
    case FIELD_NAME:
    case END_OBJECT:
    case END_ARRAY:
    case NOT_AVAILABLE:
      // error
      String msg = String.format("Unhandled JsonToken %s.",
          toString(parser, resource));
      LOGGER.error(msg);
      throw new UnsupportedOperationException(msg);
    }

    // advance past the value
    return parser.nextToken();
  }

  /**
   * Ensure that the current token is one of the provided tokens.
   * <p>
   * Note: This uses a Java assertion to support debugging in a whay that doesn't
   * impact parser performance during production operation.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
   * @param expectedTokens
   *          the tokens for which one is expected to match against the current
   *          token
   */
  public static void assertCurrent(
      @NonNull JsonParser parser,
      @NonNull URI resource,
      @NonNull JsonToken... expectedTokens) {
    JsonToken current = parser.currentToken();
    assert Arrays.stream(expectedTokens)
        .anyMatch(expected -> expected.equals(current)) : generateExpectedMessage(
            parser,
            resource,
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
   * @param resource
   *          the resource being parsed
   * @param expectedToken
   *          the expected token
   * @return the next token
   * @throws IOException
   *           if an error occurred while reading the token stream
   */
  @Nullable
  public static JsonToken assertAndAdvance(
      @NonNull JsonParser parser,
      @NonNull URI resource,
      @NonNull JsonToken expectedToken)
      throws IOException {
    JsonToken token = parser.currentToken();
    assert expectedToken.equals(token) : generateExpectedMessage(
        parser,
        resource,
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
   * @param resource
   *          the resource being parsed
   * @param expectedToken
   *          the expected token
   * @return the next token
   * @throws IOException
   *           if an error occurred while reading the token stream
   */
  @Nullable
  public static JsonToken advanceAndAssert(
      @NonNull JsonParser parser,
      @NonNull URI resource,
      @NonNull JsonToken expectedToken)
      throws IOException {
    JsonToken token = parser.nextToken();
    assert expectedToken.equals(token) : generateExpectedMessage(
        parser,
        resource,
        expectedToken,
        token);
    return token;
  }

  /**
   * Generate a message intended for error reporting based on a presumed token.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
   * @param expectedToken
   *          the expected token
   * @param actualToken
   *          the actual token found
   * @return the message string
   */
  @NonNull
  private static String generateExpectedMessage(
      @NonNull JsonParser parser,
      @NonNull URI resource,
      @NonNull JsonToken expectedToken,
      JsonToken actualToken) {
    return ObjectUtils.notNull(
        String.format("Expected JsonToken '%s', but found JsonToken '%s'%s.",
            expectedToken,
            actualToken,
            generateLocationMessage(parser, resource)));
  }

  /**
   * Generate a message intended for error reporting based on a presumed set of
   * tokens.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
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
      @NonNull URI resource,
      @NonNull JsonToken[] expectedTokens,
      JsonToken actualToken) {
    List<JsonToken> expectedTokensList = ObjectUtils.notNull(Arrays.asList(expectedTokens));
    return generateExpectedMessage(parser, resource, expectedTokensList, actualToken);
  }

  /**
   * Generate a message intended for error reporting based on a presumed set of
   * tokens.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
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
      @NonNull URI resource,
      @NonNull Collection<JsonToken> expectedTokens,
      JsonToken actualToken) {
    return ObjectUtils.notNull(
        String.format("Expected JsonToken(s) '%s', but found JsonToken '%s'%s.",
            expectedTokens.stream().map(Enum::name).collect(CustomCollectors.joiningWithOxfordComma("or")),
            actualToken,
            generateLocationMessage(parser, resource)));
  }

  /**
   * Generate a location string for the current location in the JSON token stream.
   *
   * @param parser
   *          the JSON parser
   * @param resource
   *          the resource being parsed
   * @return the location string
   */
  @NonNull
  public static CharSequence generateLocationMessage(@NonNull JsonParser parser, @NonNull URI resource) {
    JsonLocation location = parser.currentLocation();
    return location == null
        ? " in '" + resource.toString() + "'"
        : generateLocationMessage(location, resource);
  }

  /**
   * Generate a location string for the current location in the JSON token stream.
   *
   * @param location
   *          a JSON token stream location
   * @param resource
   *          the resource being parsed
   * @return the location string
   */
  @SuppressWarnings("null")
  @NonNull
  public static CharSequence generateLocationMessage(@NonNull JsonLocation location, @NonNull URI resource) {
    return new StringBuilder()
        .append(" in '")
        .append(resource.toString())
        .append("' at '")
        .append(location.getLineNr())
        .append(':')
        .append(location.getColumnNr())
        .append('\'');
  }
}
