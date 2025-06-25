/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.processor.command;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.core.util.UriUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A base class for terminal commands in the command processing hierarchy.
 * Terminal commands represent leaf nodes that perform actual operations and
 * cannot have child commands.
 */
public abstract class AbstractTerminalCommand implements ICommand {
  private static Lazy<Path> currentWorkingDirectory = Lazy.of(() -> Paths.get(System.getProperty("user.dir")));

  /**
   * A utility method that can be used to get the current working directory.
   * <p>
   * This method is thread-safe due to lazy initialization.
   *
   * @return the current working directory
   */
  @NonNull
  protected static Path getCurrentWorkingDirectory() {
    return ObjectUtils.notNull(currentWorkingDirectory.get());
  }

  /**
   * A utility method that can be used to resolve a path against the current
   * working directory.
   * <p>
   * If the path is already absolute, then the provided path is returned.
   *
   * @param path
   *          the path to resolve
   *
   * @return the resolved path
   */
  @NonNull
  protected static Path resolveAgainstCWD(@NonNull Path path) {

    return path.isAbsolute()
        ? path
        : ObjectUtils.notNull(getCurrentWorkingDirectory().resolve(path).normalize());
  }

  /**
   * A utility method that can be used to resolve a URI against the URI for the
   * current working directory.
   * <p>
   * If the URI is already absolute, then the provided URI is returned.
   * <p>
   * The path is normalized after resolution to remove any redundant name elements
   * (like "." or "..").
   *
   *
   * @param uri
   *          the uri to resolve
   *
   * @return the resolved URI
   */
  @NonNull
  protected static URI resolveAgainstCWD(@NonNull URI uri) {
    return uri.isAbsolute()
        ? uri
        : ObjectUtils.notNull(getCurrentWorkingDirectory().toUri().resolve(uri.normalize()));
  }

  /**
   * A utility method that can be used to resolve a URI (as a string) against the
   * URI for the current working directory.
   *
   * @param uri
   *          the uri to resolve
   * @return the resolved URI
   * @throws URISyntaxException
   *           if the provided URI is not a valid URI
   */
  @NonNull
  protected static URI resolveAgainstCWD(@NonNull String uri) throws URISyntaxException {
    return UriUtils.toUri(uri, ObjectUtils.notNull(getCurrentWorkingDirectory().toUri()));
  }
}
