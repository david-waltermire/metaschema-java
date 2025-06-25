/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;

import gov.nist.secauto.metaschema.core.configuration.IConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.io.AbstractDeserializer;
import gov.nist.secauto.metaschema.databind.io.DeserializationFeature;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Provides support for reading JSON-based data based on a bound Metaschema
 * module.
 *
 * @param <CLASS>
 *          the Java type of the bound object representing the root node to read
 */
public class DefaultJsonDeserializer<CLASS extends IBoundObject>
    extends AbstractDeserializer<CLASS> {
  private Lazy<JsonFactory> factory;

  /**
   * Construct a new JSON deserializer that will parse the bound class identified
   * by the {@code classBinding}.
   *
   * @param definition
   *          the bound class information for the Java type this deserializer is
   *          operating on
   */
  public DefaultJsonDeserializer(@NonNull IBoundDefinitionModelAssembly definition) {
    super(definition);
    resetFactory();
  }

  /**
   * For use by subclasses to reset the underlying JSON factory when an important
   * change has occurred that will change how the factory produces a
   * {@link JsonParser}.
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
  @NonNull
  protected JsonFactory newFactoryInstance() {
    return JsonFactoryFactory.instance();
  }

  /**
   * Get the parser factory associated with this deserializer.
   *
   * @return the factory instance
   */
  @NonNull
  protected JsonFactory getJsonFactory() {
    return ObjectUtils.notNull(factory.get());
  }

  /**
   * Using the managed JSON factory, create a new JSON parser instance using the
   * provided reader.
   *
   * @param reader
   *          the reader for the parser to read data from
   * @return the new parser
   * @throws IOException
   *           if an error occurred while creating the parser
   */
  @SuppressWarnings("resource") // reader resource not owned
  @NonNull
  protected final JsonParser newJsonParser(@NonNull Reader reader) throws IOException {
    return ObjectUtils.notNull(getJsonFactory().createParser(reader));
  }

  @Override
  protected INodeItem deserializeToNodeItemInternal(@NonNull Reader reader, @NonNull URI documentUri)
      throws IOException {
    INodeItem retval;
    try (JsonParser jsonParser = newJsonParser(reader)) {
      MetaschemaJsonReader parser = new MetaschemaJsonReader(jsonParser, documentUri);
      IBoundDefinitionModelAssembly definition = getDefinition();
      IConfiguration<DeserializationFeature<?>> configuration = getConfiguration();

      if (definition.isRoot()
          && configuration.isFeatureEnabled(DeserializationFeature.DESERIALIZE_JSON_ROOT_PROPERTY)) {
        // now parse the root property
        CLASS value = ObjectUtils.requireNonNull(parser.readObjectRoot(
            definition,
            ObjectUtils.notNull(definition.getRootJsonName())));

        retval = INodeItemFactory.instance().newDocumentNodeItem(definition, documentUri, value);
      } else {
        // read the top-level definition
        CLASS value = ObjectUtils.asType(parser.readObject(definition));

        retval = INodeItemFactory.instance().newAssemblyNodeItem(definition, documentUri, value);
      }
      return retval;
    }
  }

  @Override
  public CLASS deserializeToValueInternal(@NonNull Reader reader, @NonNull URI documentUri) throws IOException {
    try (JsonParser jsonParser = newJsonParser(reader)) {
      MetaschemaJsonReader parser = new MetaschemaJsonReader(jsonParser, documentUri);
      IBoundDefinitionModelAssembly definition = getDefinition();
      IConfiguration<DeserializationFeature<?>> configuration = getConfiguration();

      CLASS retval;
      if (definition.isRoot()
          && configuration.isFeatureEnabled(DeserializationFeature.DESERIALIZE_JSON_ROOT_PROPERTY)) {

        // now parse the root property
        retval = ObjectUtils.requireNonNull(parser.readObjectRoot(
            definition,
            ObjectUtils.notNull(definition.getRootJsonName())));
      } else {
        // read the top-level definition
        retval = ObjectUtils.asType(ObjectUtils.requireNonNull(
            parser.readObject(definition)));
      }
      return retval;
    }
  }
}
