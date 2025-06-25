/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.markup.flexmark.impl;

import com.vladsch.flexmark.ext.escaped.character.EscapedCharacterExtension;
import com.vladsch.flexmark.ext.gfm.strikethrough.SubscriptExtension;
import com.vladsch.flexmark.ext.superscript.SuperscriptExtension;
import com.vladsch.flexmark.ext.tables.TablesExtension;
import com.vladsch.flexmark.ext.typographic.TypographicExtension;
import com.vladsch.flexmark.formatter.Formatter;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.html2md.converter.FlexmarkHtmlConverter;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.parser.ParserEmulationProfile;
import com.vladsch.flexmark.util.data.DataHolder;
import com.vladsch.flexmark.util.data.DataSet;
import com.vladsch.flexmark.util.data.MutableDataSet;
import com.vladsch.flexmark.util.format.options.ListBulletMarker;
import com.vladsch.flexmark.util.misc.Extension;

import gov.nist.secauto.metaschema.core.datatype.markup.flexmark.HtmlQuoteTagExtension;
import gov.nist.secauto.metaschema.core.datatype.markup.flexmark.InsertAnchorExtension;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * This class manages a shared Flexmark configuration for use by other
 * implementations.
 */
public final class FlexmarkConfiguration {

  @NonNull
  private static final ParserEmulationProfile PARSER_PROFILE = ParserEmulationProfile.COMMONMARK_0_29;

  /**
   * The shared Flexmark configuration.
   */
  @NonNull
  private static final Lazy<DataSet> FLEXMARK_CONFIG
      = ObjectUtils.notNull(Lazy.of(() -> {
        MutableDataSet options = new MutableDataSet();
        options.setFrom(PARSER_PROFILE);

        List<Extension> extensions = List.of(
            // Metaschema insert
            InsertAnchorExtension.newInstance(),
            // q tag handling
            HtmlQuoteTagExtension.newInstance(),
            TypographicExtension.create(),
            TablesExtension.create(),
            // fix for code handling
            HtmlCodeRenderExtension.newInstance(),
            // to ensure that escaped characters are not lost
            EscapedCharacterExtension.create(),
            SuperscriptExtension.create(),
            SubscriptExtension.create()
        // AutolinkExtension.create()
        );

        Parser.EXTENSIONS.set(options, extensions);

        // AST processing expects this
        Parser.FENCED_CODE_CONTENT_BLOCK.set(options, true);
        // Parser.CODE_SOFT_LINE_BREAKS.set(options, true);
        // Parser.PARSE_INNER_HTML_COMMENTS.set(options, true);
        // Parser.HTML_BLOCK_COMMENT_ONLY_FULL_LINE.set(options, true);
        // Parser.HTML_COMMENT_BLOCKS_INTERRUPT_PARAGRAPH.set(options, true);

        // disable the built in processor, since we are configuring a patched one
        Parser.ASTERISK_DELIMITER_PROCESSOR.set(options, false);

        // configure GitHub-flavored tables
        TablesExtension.COLUMN_SPANS.set(options, false);
        TablesExtension.APPEND_MISSING_COLUMNS.set(options, true);
        TablesExtension.DISCARD_EXTRA_COLUMNS.set(options, true);
        TablesExtension.HEADER_SEPARATOR_COLUMN_MATCH.set(options, true);

        // TypographicExtension.ENABLE_QUOTES.set(options, true); // default
        TypographicExtension.ENABLE_SMARTS.set(options, false);
        TypographicExtension.SINGLE_QUOTE_UNMATCHED.set(options, "'");
        TypographicExtension.DOUBLE_QUOTE_OPEN.set(options, "\"");
        TypographicExtension.DOUBLE_QUOTE_CLOSE.set(options, "\"");

        Map<String, String> typographicReplacementMap = new ConcurrentHashMap<>();
        typographicReplacementMap.put("“", "\"");
        typographicReplacementMap.put("”", "\"");
        typographicReplacementMap.put("&ldquo;", "“");
        typographicReplacementMap.put("&rdquo;", "”");
        // typographicReplacementMap.put("‘", "'");
        // typographicReplacementMap.put("’", "'");
        typographicReplacementMap.put("&lsquo;", "‘");
        typographicReplacementMap.put("&rsquo;", "’");
        typographicReplacementMap.put("&apos;", "’");
        // typographicReplacementMap.put("«", "<<");
        typographicReplacementMap.put("&laquo;", "«");
        // typographicReplacementMap.put("»", ">>");
        typographicReplacementMap.put("&raquo;", "»");
        // typographicReplacementMap.put("…", "...");
        typographicReplacementMap.put("&hellip;", "…");
        // typographicReplacementMap.put("–", "--");
        typographicReplacementMap.put("&endash;", "–");
        // typographicReplacementMap.put("—", "---");
        typographicReplacementMap.put("&emdash;", "—");

        FlexmarkHtmlConverter.TYPOGRAPHIC_REPLACEMENT_MAP.set(options, typographicReplacementMap);
        FlexmarkHtmlConverter.OUTPUT_UNKNOWN_TAGS.set(options, true);
        FlexmarkHtmlConverter.SETEXT_HEADINGS.set(options, false); // disable
        // needed to ensure extra empty paragraphs are ignored
        FlexmarkHtmlConverter.BR_AS_EXTRA_BLANK_LINES.set(options, false);

        // FlexmarkHtmlConverter.RENDER_COMMENTS.set(options, true);
        // FlexmarkHtmlConverter.ADD_TRAILING_EOL.set(options, false); // default

        Formatter.MAX_TRAILING_BLANK_LINES.set(options, -1);
        Formatter.LIST_BULLET_MARKER.set(options, ListBulletMarker.DASH);

        HtmlRenderer.MAX_TRAILING_BLANK_LINES.set(options, -1);
        HtmlRenderer.UNESCAPE_HTML_ENTITIES.set(options, true);
        HtmlRenderer.PERCENT_ENCODE_URLS.set(options, true);
        // HtmlRenderer.ESCAPE_HTML_COMMENT_BLOCKS.set(options, false); // default
        // HtmlRenderer.SUPPRESS_HTML_COMMENT_BLOCKS.set(options, false); // default
        // HtmlRenderer.SUPPRESS_INLINE_HTML_COMMENTS.set(options, false); // default
        // HtmlRenderer.HARD_BREAK.set(options,"<br/>");

        return options.toImmutable();
      }));

  /**
   * Get the singleton configuration instance.
   *
   * @return the configuration
   */
  @NonNull
  public static DataSet instance() {
    return ObjectUtils.notNull(FLEXMARK_CONFIG.get());
  }

  /**
   * Get a new flexmark configuration.
   *
   * @param options
   *          the current set of options.
   * @return the configuration
   */
  public static DataSet newFlexmarkConfig(@Nullable DataHolder options) {
    return options == null ? instance() : DataSet.merge(instance(), options);
  }

  private FlexmarkConfiguration() {
    // disable construction
  }

}
