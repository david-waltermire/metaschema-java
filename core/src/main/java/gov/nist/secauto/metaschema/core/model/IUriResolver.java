/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;

@FunctionalInterface
public interface IUriResolver {
  /**
   * Resolve the provided URI, producing a resolved URI, which may point to a
   * different resource than the provided URI.
   *
   * @param uri
   *          the URI to resolve
   * @return the resulting URI
   */
  @NonNull
  URI resolve(@NonNull URI uri);
}
