/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;

import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.io.AbstractSerializer;
import gov.nist.secauto.metaschema.databind.io.SerializationFeature;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;

import java.io.IOException;
import java.io.Writer;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

public class DefaultJsonSerializer<CLASS extends IBoundObject>
    extends AbstractSerializer<CLASS> {
  private Lazy<JsonFactory> factory;

  /**
   * Construct a new Module binding-based deserializer that reads JSON-based
   * Module content.
   *
   * @param definition
   *          the assembly class binding describing the Java objects this
   *          deserializer parses data into
   */
  public DefaultJsonSerializer(@NonNull IBoundDefinitionModelAssembly definition) {
    super(definition);
    resetFactory();
  }

  protected final void resetFactory() {
    this.factory = Lazy.of(this::newFactoryInstance);
  }

  @Override
  protected void configurationChanged(IMutableConfiguration<SerializationFeature<?>> config) {
    super.configurationChanged(config);
    resetFactory();
  }

  /**
   * Constructs a new JSON factory.
   * <p>
   * Subclasses can override this method to create a JSON factory with a specific
   * configuration.
   *
   * @return the factory
   */
  @NonNull
  protected JsonFactory newFactoryInstance() {
    return JsonFactoryFactory.instance();
  }

  @NonNull
  private JsonFactory getJsonFactory() {
    return ObjectUtils.notNull(factory.get());
  }

  @SuppressWarnings("resource")
  @NonNull
  private JsonGenerator newJsonGenerator(@NonNull Writer writer) throws IOException {
    JsonFactory factory = getJsonFactory();
    return ObjectUtils.notNull(factory.createGenerator(writer)
        .setPrettyPrinter(new DefaultPrettyPrinter()));
  }

  @Override
  public void serialize(IBoundObject data, Writer writer) throws IOException {
    try (JsonGenerator generator = newJsonGenerator(writer)) {
      IBoundDefinitionModelAssembly definition = getDefinition();

      boolean serializeRoot = get(SerializationFeature.SERIALIZE_ROOT);
      if (serializeRoot) {
        // first write the initial START_OBJECT
        generator.writeStartObject();

        generator.writeFieldName(definition.getRootJsonName());
      }

      MetaschemaJsonWriter jsonWriter = new MetaschemaJsonWriter(generator);
      jsonWriter.write(definition, data);

      if (serializeRoot) {
        generator.writeEndObject();
      }
    }
  }
}
