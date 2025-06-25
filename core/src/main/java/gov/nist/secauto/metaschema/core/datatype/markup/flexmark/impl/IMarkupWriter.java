/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.markup.flexmark.impl;

import com.vladsch.flexmark.ast.AutoLink;
import com.vladsch.flexmark.ast.BlockQuote;
import com.vladsch.flexmark.ast.Code;
import com.vladsch.flexmark.ast.CodeBlock;
import com.vladsch.flexmark.ast.FencedCodeBlock;
import com.vladsch.flexmark.ast.HardLineBreak;
import com.vladsch.flexmark.ast.Heading;
import com.vladsch.flexmark.ast.HtmlBlock;
import com.vladsch.flexmark.ast.HtmlCommentBlock;
import com.vladsch.flexmark.ast.HtmlEntity;
import com.vladsch.flexmark.ast.HtmlInline;
import com.vladsch.flexmark.ast.Image;
import com.vladsch.flexmark.ast.IndentedCodeBlock;
import com.vladsch.flexmark.ast.Link;
import com.vladsch.flexmark.ast.ListBlock;
import com.vladsch.flexmark.ast.MailLink;
import com.vladsch.flexmark.ast.Paragraph;
import com.vladsch.flexmark.ast.Text;
import com.vladsch.flexmark.ast.TextBase;
import com.vladsch.flexmark.ast.ThematicBreak;
import com.vladsch.flexmark.ext.escaped.character.EscapedCharacter;
import com.vladsch.flexmark.ext.tables.TableBlock;
import com.vladsch.flexmark.ext.typographic.TypographicQuotes;
import com.vladsch.flexmark.ext.typographic.TypographicSmarts;
import com.vladsch.flexmark.util.ast.Node;

import gov.nist.secauto.metaschema.core.datatype.markup.flexmark.InsertAnchorExtension.InsertAnchorNode;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * A common interface for writing markup to some form of an output sync.
 *
 * @param <T>
 *          the Java type of sync to write to
 * @param <E>
 *          the Java type of exception that can be thrown when a writing error
 *          occurs
 */
@SuppressFBWarnings(value = "THROWS_METHOD_THROWS_CLAUSE_THROWABLE",
    justification = "There is a need to support varying exceptions from multiple stream writers")
public interface IMarkupWriter<T, E extends Throwable> {
  /**
   * Write an HTML element with the provided local name, with no attributes.
   *
   * @param localName
   *          the element name
   * @param node
   *          the markup node related to the element
   * @param childHandler
   *          a handler used to process child node content
   * @throws E
   *           if an error occurred while writing the markup
   */
  default void writeElement(
      @NonNull String localName,
      @NonNull Node node,
      @Nullable ChildHandler<T, E> childHandler) throws E {
    writeElement(localName, node, CollectionUtil.emptyMap(), childHandler);
  }

  /**
   * Write an HTML element with the provided local name.
   *
   * @param localName
   *          the element name
   * @param node
   *          the markup node related to the element
   * @param attributes
   *          attributes associated with the element to also write
   * @param childHandler
   *          the handler used to process child node content or {@code null}
   * @throws E
   *           if an error occurred while writing the markup
   */
  void writeElement(
      @NonNull String localName,
      @NonNull Node node,
      @NonNull Map<String, String> attributes,
      @Nullable ChildHandler<T, E> childHandler) throws E;

  /**
   * Write an empty HTML element with the provided local name.
   *
   * @param localName
   *          the element name
   * @param attributes
   *          attributes associated with the element to also write
   * @throws E
   *           if an error occurred while writing the markup
   */
  void writeEmptyElement(
      @NonNull String localName,
      @NonNull Map<String, String> attributes) throws E;

  /**
   * Write a text node.
   *
   * @param node
   *          the text node to write
   * @throws E
   *           if an error occurred while writing
   */
  void writeText(@NonNull Text node) throws E;

  /**
   * Write a combination of {@link Text} and {@link EscapedCharacter} node
   * children.
   *
   * @param node
   *          the text node to write
   * @throws E
   *           if an error occurred while writing
   */
  void writeText(@NonNull TextBase node) throws E;

  /**
   * Write a text string.
   *
   * @param text
   *          the text to write
   * @throws E
   *           if an error occurred while writing
   */
  void writeText(@NonNull CharSequence text) throws E;

  /**
   * Write an HTML entity.
   *
   * @param node
   *          the entity node
   * @throws E
   *           if an error occurred while writing
   */
  void writeHtmlEntity(@NonNull HtmlEntity node) throws E;

  /**
   * Write an HTML entity for a typographic character.
   *
   * @param node
   *          the entity node
   * @throws E
   *           if an error occurred while writing
   */
  void writeHtmlEntity(@NonNull TypographicSmarts node) throws E;

  /**
   * Write a paragraph.
   *
   * @param node
   *          the paragraph node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeParagraph(
      @NonNull Paragraph node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write a link.
   *
   * @param node
   *          the link node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeLink(
      @NonNull Link node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write an email link.
   *
   * @param node
   *          the link node
   * @throws E
   *           if an error occurred while writing
   */
  void writeLink(@NonNull MailLink node) throws E;

  /**
   * Write a link that was auto-detected.
   *
   * @param node
   *          the link node
   * @throws E
   *           if an error occurred while writing
   */
  void writeLink(@NonNull AutoLink node) throws E;

  /**
   * Write a typographic quote(s).
   *
   * @param node
   *          the quote node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeTypographicQuotes(
      @NonNull TypographicQuotes node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write embedded HTML content.
   *
   * @param node
   *          the HTML content
   * @throws E
   *           if an error occurred while writing
   */
  void writeInlineHtml(@NonNull HtmlInline node) throws E;

  /**
   * Write HTML block content.
   *
   * @param node
   *          the HTML block
   * @throws E
   *           if an error occurred while writing
   */
  void writeBlockHtml(@NonNull HtmlBlock node) throws E;

  /**
   * Write a table.
   *
   * @param node
   *          the table node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeTable(
      @NonNull TableBlock node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write an image.
   *
   * @param node
   *          the image node
   * @throws E
   *           if an error occurred while writing
   */
  void writeImage(@NonNull Image node) throws E;

  /**
   * Write a Metaschema markup insertion point.
   *
   * @param node
   *          the insert node
   * @throws E
   *           if an error occurred while writing
   */
  void writeInsertAnchor(@NonNull InsertAnchorNode node) throws E;

  /**
   * Write a heading.
   *
   * @param node
   *          the heading node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeHeading(
      @NonNull Heading node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write an inline code block.
   *
   * @param node
   *          the code node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeCode(
      @NonNull Code node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write an indented code block.
   *
   * @param node
   *          the code node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeCodeBlock(
      @NonNull IndentedCodeBlock node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write a fenced code block.
   *
   * @param node
   *          the code node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeCodeBlock(
      @NonNull FencedCodeBlock node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write a code block.
   *
   * @param node
   *          the code node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeCodeBlock(
      @NonNull CodeBlock node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write a block quotation.
   *
   * @param node
   *          the quotation node
   * @param childHandler
   *          the handler used to process child node content
   * @throws E
   *           if an error occurred while writing
   */
  void writeBlockQuote(
      @NonNull BlockQuote node,
      @NonNull ChildHandler<T, E> childHandler) throws E;

  /**
   * Write a list.
   *
   * @param localName
   *          the HTML element name to use
   * @param node
   *          the list node
   * @param handler
   *          the list item handler
   * @throws E
   *           if an error occurred while writing
   */
  void writeList(
      @NonNull String localName,
      @NonNull ListBlock node,
      @NonNull ChildHandler<T, E> handler) throws E;

  /**
   * Write a line break.
   *
   * @param node
   *          the break node
   * @throws E
   *           if an error occurred while writing
   */
  void writeBreak(@NonNull HardLineBreak node) throws E;

  /**
   * Write a line break.
   *
   * @param node
   *          the break node
   * @throws E
   *           if an error occurred while writing
   */
  void writeBreak(@NonNull ThematicBreak node) throws E;

  /**
   * Write a comment.
   *
   * @param node
   *          the comment node
   * @throws E
   *           if an error occurred while writing
   */
  void writeComment(@NonNull HtmlCommentBlock node) throws E;

  /**
   * Provides a callback to handle node children.
   *
   * @param <T>
   *          the type of stream to write to
   * @param <E>
   *          the type of exception that can be thrown when a writing error occurs
   */
  @FunctionalInterface
  interface ChildHandler<T, E extends Throwable> {
    /**
     * A callback used to process a given node.
     *
     * @param node
     *          the node to process
     * @param writer
     *          used to write if an error occurred while writing
     * @throws E
     *           if an error occurred while writing
     */
    void accept(@NonNull Node node, @NonNull IMarkupWriter<T, E> writer) throws E;
  }

}
