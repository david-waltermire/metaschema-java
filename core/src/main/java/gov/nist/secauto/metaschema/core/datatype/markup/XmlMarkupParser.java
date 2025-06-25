/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.markup;

import com.vladsch.flexmark.util.sequence.Escaping;

import gov.nist.secauto.metaschema.core.model.util.XmlEventUtil;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.stax2.XMLEventReader2;

import java.net.URI;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides utility functions to support reading and writing XML, and for
 * producing error and warning messages.
 */
public final class XmlMarkupParser {
  private static final Logger LOGGER = LogManager.getLogger(XmlMarkupParser.class);

  /**
   * The block element names that this parser supports.
   */
  @NonNull
  public static final Set<String> XHTML_BLOCK_ELEMENTS = ObjectUtils.notNull(
      Set.of(
          "h1",
          "h2",
          "h3",
          "h4",
          "h5",
          "h6",
          "ul",
          "ol",
          "pre",
          "hr",
          "blockquote",
          "p",
          "table",
          "img"));

  @NonNull
  private static final XmlMarkupParser SINGLETON = new XmlMarkupParser();

  /**
   * Get the singleton markup parser instance.
   *
   * @return the instance
   */
  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @NonNull
  public static synchronized XmlMarkupParser instance() {
    return SINGLETON;
  }

  private XmlMarkupParser() {
    // disable construction
  }

  /**
   * Parse a single line of markup from XHTML.
   *
   * @param reader
   *          the XML event stream reader
   * @param resource
   *          the resource being parsed
   * @return the markup string
   * @throws XMLStreamException
   *           if an error occurred while parsing
   */
  public MarkupLine parseMarkupline(
      @NonNull XMLEventReader2 reader,
      @NonNull URI resource) throws XMLStreamException {
    StringBuilder buffer = new StringBuilder();
    parseContents(reader, resource, null, buffer);
    String html = buffer.toString().trim();
    return html.isEmpty() ? null : MarkupLine.fromHtml(html);
  }

  /**
   * Parse a markup multiline from XHTML.
   *
   * @param reader
   *          the XML event stream reader
   * @param resource
   *          the resource being parsed
   * @return the markup string
   * @throws XMLStreamException
   *           if an error occurred while parsing
   */
  public MarkupMultiline parseMarkupMultiline(
      @NonNull XMLEventReader2 reader,
      @NonNull URI resource) throws XMLStreamException {
    StringBuilder buffer = new StringBuilder();
    parseToString(reader, resource, buffer);
    String html = buffer.toString().trim();

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("XML->HTML: {}", html);
    }
    return html.isEmpty() ? null : MarkupMultiline.fromHtml(html);
  }

  /**
   * Parse a markup multiline from XHTML.
   *
   * @param reader
   *          the XML event stream reader
   * @param resource
   *          the resource being parsed
   * @param buffer
   *          the markup string buffer
   * @throws XMLStreamException
   *           if an error occurred while parsing
   */
  private void parseToString(
      @NonNull XMLEventReader2 reader,
      @NonNull URI resource,
      @NonNull StringBuilder buffer) throws XMLStreamException {
    // if (LOGGER.isDebugEnabled()) {
    // LOGGER.debug("parseToString(enter): {}",
    // XmlEventUtil.toString(reader.peek()));
    // }

    outer: while (reader.hasNextEvent() && !reader.peek().isEndElement()) {
      // skip whitespace before the next block element
      XMLEvent nextEvent = XmlEventUtil.skipWhitespace(reader);

      // if (LOGGER.isDebugEnabled()) {
      // LOGGER.debug("parseToString: {}", XmlEventUtil.toString(nextEvent));
      // }

      if (nextEvent.isStartElement()) {
        StartElement start = nextEvent.asStartElement();
        QName name = start.getName();

        // Note: the next element is not consumed. The called method is expected to
        // consume it
        if (!XHTML_BLOCK_ELEMENTS.contains(name.getLocalPart())) {
          // throw new IllegalStateException();
          // stop parsing on first unrecognized event
          break outer;
        }
        parseStartElement(reader, resource, start, buffer);
      }
      // reader.nextEvent();

      // skip whitespace before the next block element
      XmlEventUtil.skipWhitespace(reader);
    }

    // if (LOGGER.isDebugEnabled()) {
    // LOGGER.debug("parseToString(exit): {}", reader.peek() != null ?
    // XmlEventUtil.toString(reader.peek()) : "");
    // }
  }

  private void parseStartElement(
      @NonNull XMLEventReader2 reader,
      @NonNull URI resource,
      @NonNull StartElement start,
      @NonNull StringBuilder buffer)
      throws XMLStreamException {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("parseStartElement(enter): {}", XmlEventUtil.toString(start, resource));
    }

    // consume the start event
    reader.nextEvent();

    QName name = start.getName();
    buffer.append('<')
        .append(name.getLocalPart());
    for (Attribute attribute : CollectionUtil.toIterable(
        ObjectUtils.notNull(start.getAttributes()))) {
      buffer
          .append(' ')
          .append(attribute.getName().getLocalPart())
          .append("=\"")
          .append(attribute.getValue())
          .append('"');
    }

    XMLEvent next = reader.peek();
    if (next != null && next.isEndElement()) {
      buffer.append("/>");
    } else {
      buffer.append('>');

      // parse until the start's END_ELEMENT is reached
      parseContents(reader, resource, start, buffer);

      buffer
          .append("</")
          .append(name.getLocalPart())
          .append('>');

      // the next event should be the start's END_ELEMENT
      XmlEventUtil.assertNext(reader, resource, XMLStreamConstants.END_ELEMENT, name);
    }
    // consume end element event
    reader.nextEvent();

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("parseStartElement(exit): {}",
          reader.peek() != null
              ? XmlEventUtil.toString(reader.peek(), resource)
              : "");
    }
  }

  private void parseContents(
      @NonNull XMLEventReader2 reader,
      @NonNull URI resource,
      @Nullable StartElement start,
      @NonNull StringBuilder buffer)
      throws XMLStreamException {
    // if (LOGGER.isDebugEnabled()) {
    // LOGGER.debug("parseContents(enter): {}",
    // XmlEventUtil.toString(reader.peek()));
    // }

    XMLEvent event;
    while (reader.hasNextEvent() && !(event = reader.peek()).isEndElement()) {
      // // skip whitespace before the next list item
      // event = XmlEventUtil.skipWhitespace(reader);

      // if (LOGGER.isDebugEnabled()) {
      // LOGGER.debug("parseContents(before): {}", XmlEventUtil.toString(event));
      // }

      if (event.isStartElement()) {
        StartElement nextStart = ObjectUtils.notNull(event.asStartElement());
        // QName nextName = nextStart.getName();
        parseStartElement(reader, resource, nextStart, buffer);

        // if (LOGGER.isDebugEnabled()) {
        // LOGGER.debug("parseContents(after): {}",
        // XmlEventUtil.toString(reader.peek()));
        // }

        // assert XmlEventUtil.isNextEventEndElement(reader, nextName) :
        // XmlEventUtil.toString(reader.peek());

        // reader.nextEvent();
      } else if (event.isCharacters()) {
        Characters characters = event.asCharacters();
        buffer.append(Escaping.escapeHtml(characters.getData(), true));
        reader.nextEvent();
      }
    }

    assert start == null
        || XmlEventUtil.isEventEndElement(reader.peek(), ObjectUtils.notNull(start.getName())) : XmlEventUtil
            .generateExpectedMessage(reader.peek(), resource, XMLStreamConstants.END_ELEMENT, start.getName());

    // if (LOGGER.isDebugEnabled()) {
    // LOGGER.debug("parseContents(exit): {}", reader.peek() != null ?
    // XmlEventUtil.toString(reader.peek()) : "");
    // }
  }

}
