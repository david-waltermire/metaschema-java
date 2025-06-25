/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.markup.flexmark.impl;

import com.vladsch.flexmark.util.ast.Document;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Support for visiting a Flexmark syntax tree.
 *
 * @param <T>
 *          the Java type of sync to write to
 * @param <E>
 *          the Java type of exception that can be thrown when a writing error
 *          occurs
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
@SuppressFBWarnings("THROWS_METHOD_THROWS_CLAUSE_THROWABLE")
public interface IMarkupVisitor<T, E extends Throwable> {
  /**
   * A visitor callback used to visit a markdown syntax tree.
   *
   * @param document
   *          the markdown syntax tree
   * @param writer
   *          a markup writer used to generate markup output
   * @throws E
   *           the visitor exception Java type
   */
  void visitDocument(@NonNull Document document, @NonNull IMarkupWriter<T, E> writer) throws E;
}
