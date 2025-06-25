/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.util;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;

class UriUtilsTest {
  private static Stream<Arguments> provideValuesTestToUri() throws MalformedURLException, URISyntaxException {
    String base = Paths.get(System.getProperty("user.dir")).toUri().toURL().toURI().toASCIIString();
    return Stream.of(
        Arguments.of("http://example.org/valid", "http://example.org/valid", true),
        Arguments.of("https://example.org/valid", "https://example.org/valid", true),
        Arguments.of("http://example.org/valid", "http://example.org/valid", true),
        Arguments.of("ftp://example.org/valid", "ftp://example.org/valid", true),
        // Arguments.of("ssh://example.org/valid", "ssh://example.org/valid", true),
        Arguments.of("example.org/good", base + "example.org/good", true),
        Arguments.of("bad.txt", base + "bad.txt", true),
        // Arguments.of("relative\\windows\\path\\resource.txt", base +
        // "relative/windows/path/resource.txt", true),
        // Arguments.of("C:\\absolute\\valid.txt", "C:\\absolute\\valid.txt",true),
        Arguments.of("local/relative/path/is/invalid.txt", base + "local/relative/path/is/invalid.txt", true),
        // Arguments.of("/absolute/local/path/is/invalid.txt", true),
        Arguments.of("1;", base + "1;", true));
  }

  @ParameterizedTest
  @MethodSource("provideValuesTestToUri")
  void testToUri(@NonNull String location, @NonNull String expectedLocation, boolean expectedResult)
      throws MalformedURLException {
    Path cwd = Paths.get(System.getProperty("user.dir"));
    try {
      URI uri = UriUtils.toUri(location, ObjectUtils.notNull(cwd.toUri())).normalize().toURL().toURI();
      System.out.println(String.format("%s -> %s", location, uri.toASCIIString()));
      assertAll(
          () -> assertEquals(uri.toASCIIString(), expectedLocation),
          () -> assertTrue(expectedResult));
    } catch (URISyntaxException ex) {
      // this resulted in an invalid uri, ensure that the expectation is false
      assertFalse(expectedResult);
    }
  }

  private static Stream<Arguments> provideArgumentsTestRelativize() {
    return Stream.of(
        Arguments.of(
            "http://example.com/this/file1.txt",
            "http://example.com/this/file2.txt",
            true,
            "file2.txt"),
        Arguments.of(
            "http://example.com/this",
            "http://example.com/this/that",
            true,
            "that"),
        Arguments.of(
            "http://example.com/this/",
            "http://example.com/this/that",
            true,
            "that"),
        Arguments.of(
            "http://example.com/this/that",
            "http://example.com/this/new",
            true,
            "new"),
        Arguments.of(
            "http://example.com/this/that/A",
            "http://example.com/this/new/B",
            true,
            "../new/B"),
        Arguments.of(
            "http://example.com/this/that/",
            "http://example.com/this/new/",
            true,
            "../new/"),
        Arguments.of(
            "http://example.com/this/that/A/",
            "http://example.com/this/new/B",
            true,
            "../../new/B"),
        Arguments.of(
            "http://example.com/this/that/A/X/file1,text",
            "http://example.com/this/that/A/file2.txt",
            true,
            "../file2.txt"),
        Arguments.of(
            "http://example.com/this/that/A/",
            "http://example.org/this/new/B",
            true,
            "http://example.org/this/new/B"));
  }

  @ParameterizedTest
  @MethodSource("provideArgumentsTestRelativize")
  void testRelativize(@NonNull String uri1, @NonNull String uri2, boolean prepend, @NonNull String expected)
      throws URISyntaxException {
    URI thisUri = URI.create(uri1);
    URI thatUri = URI.create(uri2);

    URI result = UriUtils.relativize(thisUri, thatUri, prepend);
    assertEquals(expected, result.toASCIIString());
  }
}
