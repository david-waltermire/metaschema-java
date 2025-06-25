/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.markup.flexmark;

import com.vladsch.flexmark.formatter.Formatter;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.html2md.converter.FlexmarkHtmlConverter;
import com.vladsch.flexmark.parser.ListOptions;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.data.DataHolder;

import gov.nist.secauto.metaschema.core.datatype.markup.flexmark.impl.FixedEmphasisDelimiterProcessor;
import gov.nist.secauto.metaschema.core.datatype.markup.flexmark.impl.FlexmarkConfiguration;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides factory methods for Flexmark processing to support HTML-to-markdown
 * and markdown-to-HTML conversion.
 */
public final class FlexmarkFactory {
  @NonNull
  private static final FlexmarkFactory SINGLETON = new FlexmarkFactory();
  @NonNull
  private final Parser markdownParser;
  @NonNull
  private final HtmlRenderer htmlRenderer;
  @NonNull
  private final Formatter formatter;
  @NonNull
  private final FlexmarkHtmlConverter htmlConverter;
  @NonNull
  final ListOptions listOptions;

  /**
   * Get the static Flexmark factory instance.
   *
   * @return the instance
   */
  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @NonNull
  public static synchronized FlexmarkFactory instance() {
    return SINGLETON;
  }

  /**
   * Get a Flexmark factory instance that uses the provided Flexmark
   * configuration.
   *
   * @param config
   *          the Flexmark configuration
   * @return the instance
   */
  @NonNull
  public static FlexmarkFactory newInstance(@NonNull DataHolder config) {
    return new FlexmarkFactory(config);
  }

  private FlexmarkFactory() {
    this(FlexmarkConfiguration.instance());
  }

  @SuppressWarnings("null")
  private FlexmarkFactory(@NonNull DataHolder config) {
    this.markdownParser = Parser.builder(config)
        .customDelimiterProcessor(new FixedEmphasisDelimiterProcessor(Parser.STRONG_WRAPS_EMPHASIS.get(config)))
        .build();
    this.htmlRenderer = HtmlRenderer.builder(config).build();
    this.formatter = Formatter.builder(config).build();
    this.htmlConverter = FlexmarkHtmlConverter.builder(config).build();
    this.listOptions = ListOptions.get(config);
  }

  /**
   * Get configured options for processing HTML and markdown lists.
   *
   * @return the options
   */
  @NonNull
  public ListOptions getListOptions() {
    return listOptions;
  }

  /**
   * Get the Flexmark markdown parser, which can produce a markdown syntax tree.
   *
   * @return the parser
   */
  @NonNull
  public Parser getMarkdownParser() {
    return markdownParser;
  }

  /**
   * Get the Flexmark HTML renderer, which can produce HTML from a markdown syntax
   * tree.
   *
   * @return the parser
   */
  @NonNull
  public HtmlRenderer getHtmlRenderer() {
    return htmlRenderer;
  }

  /**
   * Get the Flexmark formatter, which can produce markdown from a markdown syntax
   * tree.
   *
   * @return the parser
   */
  @NonNull
  public Formatter getFormatter() {
    return formatter;
  }

  /**
   * Get the Flexmark HTML converter, which can produce markdown from HTML
   * content.
   *
   * @return the parser
   */
  @NonNull
  public FlexmarkHtmlConverter getFlexmarkHtmlConverter() {
    return htmlConverter;
  }
}
