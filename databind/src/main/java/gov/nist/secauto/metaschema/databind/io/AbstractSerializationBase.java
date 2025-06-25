/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io;

import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IConfigurationFeature;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;

abstract class AbstractSerializationBase<T extends IConfigurationFeature<?>>
    implements IMutableConfiguration<T> {
  @NonNull
  private final IBoundDefinitionModelAssembly definition;
  @NonNull
  private final DefaultConfiguration<T> configuration;

  protected AbstractSerializationBase(@NonNull IBoundDefinitionModelAssembly definition) {
    this.definition = definition;
    this.configuration = new DefaultConfiguration<>();
  }

  /**
   * Retrieve the binding context associated with the serializer.
   *
   * @return the binding context
   */
  @NonNull
  protected IBindingContext getBindingContext() {
    return getDefinition().getBindingContext();
  }

  /**
   * Retrieve the bound class information associated with the assembly that the
   * serializer/deserializer will write/read data from.
   *
   * @return the class binding for the Module assembly
   */
  @NonNull
  protected IBoundDefinitionModelAssembly getDefinition() {
    return definition;
  }

  @SuppressWarnings("unused")
  protected void configurationChanged(@NonNull IMutableConfiguration<T> config) {
    // do nothing by default. Methods can override this to deal with factory caching
  }

  /**
   * Get the current configuration of the serializer/deserializer.
   *
   * @return the configuration
   */
  @NonNull
  protected IMutableConfiguration<T> getConfiguration() {
    return configuration;
  }

  @Override
  public boolean isFeatureEnabled(T feature) {
    return configuration.isFeatureEnabled(feature);
  }

  @Override
  public Map<T, Object> getFeatureValues() {
    return configuration.getFeatureValues();
  }

  @Override
  public <V> V get(T feature) {
    return configuration.get(feature);
  }

}
