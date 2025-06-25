/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A collection of methods for manipulating uniform resource identifiers (URIs),
 * providing functionality for URI resolution, relativization, and path
 * manipulation.
 * <p>
 * This utility class supports both local file paths and remote URIs.
 */
public final class UriUtils {
  private static final Pattern URI_SEPERATOR_PATTERN = Pattern.compile("\\/");
  private static final String URI_SEPERATOR = "/";

  private UriUtils() {
    // disable construction
  }

  /**
   * Process a string to a local file path or remote location. If the location is
   * convertible to a URI, return the {@link URI}. Normalize the resulting URI
   * with the base URI, if provided.
   *
   * @param location
   *          a string defining a remote or local file-based location
   * @param baseUri
   *          the base URI to use for URI normalization
   * @return a new URI
   * @throws URISyntaxException
   *           if the location string is not convertible to URI
   */
  @SuppressWarnings("PMD.PreserveStackTrace")
  @NonNull
  public static URI toUri(@NonNull String location, @NonNull URI baseUri) throws URISyntaxException {
    URI asUri;
    try {
      asUri = new URI(location);
    } catch (URISyntaxException ex) {
      // the location is not a valid URI
      try {
        // try to parse the location as a local file path
        Path path = Paths.get(location);
        asUri = path.toUri();
      } catch (InvalidPathException ex2) {
        // not a local file path, so rethrow the original URI exception
        throw ex;
      }
    }
    return ObjectUtils.notNull(baseUri.resolve(asUri.normalize()));
  }

  /**
   * This function extends the functionality of {@link URI#relativize(URI)} by
   * supporting relative reference pathing (e.g., ..), when the {@code prepend}
   * parameter is set to {@code true}.
   *
   * @param base
   *          the URI to relativize against
   * @param other
   *          the URI to make relative
   * @param prepend
   *          if {@code true}, then prepend relative pathing
   * @return a new relative URI
   * @throws URISyntaxException
   *           if any of the URIs are malformed
   */
  @NonNull
  public static URI relativize(URI base, URI other, boolean prepend) throws URISyntaxException {
    URI normBase = Objects.requireNonNull(base).normalize();
    URI normOther = Objects.requireNonNull(other).normalize();
    URI retval = ObjectUtils.notNull(normBase.relativize(normOther));

    if (prepend && !normBase.isOpaque() && !retval.isOpaque() && hasSameSchemeAndAuthority(normBase, retval)) {
      // the URIs are not opaque and they share the same scheme and authority
      String basePath = normBase.getPath();
      String targetPath = normOther.getPath();
      String newPath = prependRelativePath(basePath, targetPath);

      retval = new URI(null, null, newPath, normOther.getQuery(), normOther.getFragment());
    }
    return retval;
  }

  private static boolean hasSameSchemeAndAuthority(URI base, URI other) {
    String baseScheme = base.getScheme();
    boolean retval = baseScheme == null && other.getScheme() == null
        || baseScheme != null && baseScheme.equals(other.getScheme());
    String baseAuthority = base.getAuthority();
    return retval && (baseAuthority == null && other.getAuthority() == null
        || baseAuthority != null && baseAuthority.equals(other.getAuthority()));
  }

  /**
   * Get the path of the provided target relative to the path of the provided
   * base.
   *
   * @param base
   *          the base path to resolve against
   * @param target
   *          the URI to relativize against the base
   * @return the relativized URI
   */
  @SuppressWarnings("PMD.CyclomaticComplexity")
  public static String prependRelativePath(String base, String target) {
    // based on code from
    // http://stackoverflow.com/questions/10801283/get-relative-path-of-two-uris-in-java

    // Split paths into segments
    String[] baseSegments = URI_SEPERATOR_PATTERN.split(base);
    String[] targetSegments = URI_SEPERATOR_PATTERN.split(target, -1);

    // Discard trailing segment of base path, since this resource doesn't matter
    if (baseSegments.length > 0 && !base.endsWith(URI_SEPERATOR)) {
      baseSegments = Arrays.copyOf(baseSegments, baseSegments.length - 1);
    }

    // Remove common prefix segments
    int segmentIndex = 0;
    while (segmentIndex < baseSegments.length && segmentIndex < targetSegments.length
        && baseSegments[segmentIndex].equals(targetSegments[segmentIndex])) {
      segmentIndex++;
    }

    // Construct the relative path
    StringBuilder retval = new StringBuilder();
    for (int j = 0; j < baseSegments.length - segmentIndex; j++) {
      retval.append("..");
      if (retval.length() != 0) {
        retval.append(URI_SEPERATOR);
      }
    }

    for (int j = segmentIndex; j < targetSegments.length; j++) {
      retval.append(targetSegments[j]);
      if (retval.length() != 0 && j < targetSegments.length - 1) {
        retval.append(URI_SEPERATOR);
      }
    }
    return retval.toString();
  }
}
