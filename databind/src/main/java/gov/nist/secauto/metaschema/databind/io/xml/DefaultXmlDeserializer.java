/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io.xml;

import com.ctc.wstx.stax.WstxInputFactory;

import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.util.AutoCloser;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.io.AbstractDeserializer;
import gov.nist.secauto.metaschema.databind.io.DeserializationFeature;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;

import org.codehaus.stax2.XMLEventReader2;
import org.codehaus.stax2.XMLInputFactory2;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;

import javax.xml.stream.EventFilter;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Provides support for reading XML-based data based on a bound Metaschema
 * module.
 *
 * @param <CLASS>
 *          the Java type of the bound object representing the root node to read
 */
public class DefaultXmlDeserializer<CLASS extends IBoundObject>
    extends AbstractDeserializer<CLASS> {
  private Lazy<XMLInputFactory2> factory;

  @NonNull
  private final IBoundDefinitionModelAssembly rootDefinition;

  /**
   * Construct a new Module binding-based deserializer that reads XML-based Module
   * content.
   *
   * @param definition
   *          the assembly class binding describing the Java objects this
   *          deserializer parses data into
   */
  @SuppressFBWarnings(value = "CT_CONSTRUCTOR_THROW", justification = "Use of final fields")
  public DefaultXmlDeserializer(@NonNull IBoundDefinitionModelAssembly definition) {
    super(definition);
    this.rootDefinition = definition;
    if (!definition.isRoot()) {
      throw new UnsupportedOperationException(
          String.format("The assembly '%s' is not a root assembly.", definition.getBoundClass().getName()));
    }
    resetFactory();
  }

  /**
   * For use by subclasses to reset the underlying XML factory when an important
   * change has occurred that will change how the factory produces an
   * {@link XMLInputFactory2}.
   */
  protected final void resetFactory() {
    this.factory = Lazy.of(this::newFactoryInstance);
  }

  @Override
  protected void configurationChanged(IMutableConfiguration<DeserializationFeature<?>> config) {
    super.configurationChanged(config);
    resetFactory();
  }

  /**
   * Get a JSON factory instance.
   * <p>
   * This method can be used by sub-classes to create a customized factory
   * instance.
   *
   * @return the factory
   */
  @SuppressWarnings("resource")
  @NonNull
  protected XMLInputFactory2 newFactoryInstance() {
    XMLInputFactory2 retval = (XMLInputFactory2) XMLInputFactory.newInstance();
    assert retval instanceof WstxInputFactory;
    retval.configureForXmlConformance();
    retval.setProperty(XMLInputFactory.IS_COALESCING, false);
    retval.setProperty(XMLInputFactory2.P_PRESERVE_LOCATION, true);
    // xmlInputFactory.configureForSpeed();

    if (isFeatureEnabled(DeserializationFeature.DESERIALIZE_XML_ALLOW_ENTITY_RESOLUTION)) {
      retval.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, true);
      retval.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
      retval.setProperty(XMLInputFactory.SUPPORT_DTD, true);
      retval.setProperty(XMLInputFactory.RESOLVER,
          (XMLResolver) (publicID, systemID, baseURI, namespace) -> {
            URI base = URI.create(baseURI);
            URI resource = base.resolve(systemID);
            try {

              return ObjectUtils.notNull(resource.toURL().openStream());
            } catch (IOException ex) {
              throw new XMLStreamException(ex);
            }
          });
    }
    return retval;
  }

  /**
   * Get the XML input factory instance used to create XML parser instances.
   * <p>
   * Uses a built-in default if a user specified factory is not provided.
   *
   * @return the factory instance
   * @see #setXMLInputFactory(XMLInputFactory2)
   */
  @NonNull
  private XMLInputFactory2 getXMLInputFactory() {
    return ObjectUtils.notNull(factory.get());
  }

  @NonNull
  private XMLEventReader2 newXMLEventReader2(
      @NonNull URI documentUri,
      @NonNull Reader reader) throws XMLStreamException {
    XMLEventReader2 eventReader
        = (XMLEventReader2) getXMLInputFactory().createXMLEventReader(documentUri.toASCIIString(), reader);
    EventFilter filter = new CommentFilter();
    return ObjectUtils.notNull((XMLEventReader2) getXMLInputFactory().createFilteredReader(eventReader, filter));
  }

  @Override
  protected final IDocumentNodeItem deserializeToNodeItemInternal(Reader reader, URI documentUri) throws IOException {
    Object value = deserializeToValueInternal(reader, documentUri);
    return INodeItemFactory.instance().newDocumentNodeItem(rootDefinition, documentUri, value);
  }

  @Override
  public final CLASS deserializeToValueInternal(Reader reader, URI resource) throws IOException {
    // doesn't auto close the underlying reader
    try (AutoCloser<XMLEventReader2, XMLStreamException> closer = AutoCloser.autoClose(
        newXMLEventReader2(resource, reader), XMLEventReader::close)) {
      return parseXmlInternal(closer.getResource(), resource);
    } catch (XMLStreamException ex) {
      throw new IOException("Unable to create a new XMLEventReader2 instance.", ex);
    }
  }

  @NonNull
  private CLASS parseXmlInternal(@NonNull XMLEventReader2 reader, @NonNull URI resource)
      throws IOException {

    MetaschemaXmlReader parser = new MetaschemaXmlReader(reader, resource, new DefaultXmlProblemHandler());

    try {
      return parser.read(rootDefinition);
    } catch (IOException | AssertionError ex) {
      throw new IOException(
          String.format("An unexpected error occurred during parsing: %s", ex.getMessage()),
          ex);
    }
  }
}
