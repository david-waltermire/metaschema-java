/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.codegen.typeinfo.def;

import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelAbsolute;
import gov.nist.secauto.metaschema.core.model.IInstance;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IInstanceTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IModelInstanceTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IPropertyTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.ITypeResolver;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class AssemblyDefinitionTypeInfoImpl
    extends AbstractModelDefinitionTypeInfo<IAssemblyDefinition>
    implements IAssemblyDefinitionTypeInfo {
  private static final Logger LOGGER = LogManager.getLogger(AssemblyDefinitionTypeInfoImpl.class);

  @NonNull
  private final Lazy<Map<String, IPropertyTypeInfo>> propertyNameToTypeInfoMap;
  @NonNull
  private final Lazy<Map<IInstance, IInstanceTypeInfo>> instanceToTypeInfoMap;

  public AssemblyDefinitionTypeInfoImpl(@NonNull IAssemblyDefinition definition, @NonNull ITypeResolver typeResolver) {
    super(definition, typeResolver);
    this.instanceToTypeInfoMap = ObjectUtils.notNull(Lazy.of(() -> Stream.concat(
        getFlagInstanceTypeInfos().stream(),
        processModel(definition))
        .collect(CustomCollectors.toMap(
            IInstanceTypeInfo::getInstance,
            CustomCollectors.identity(),
            (key, v1, v2) -> {
              if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("Unexpected duplicate property name '%s'", key));
              }
              return ObjectUtils.notNull(v2);
            },
            LinkedHashMap::new))));
    this.propertyNameToTypeInfoMap = ObjectUtils.notNull(Lazy.of(() -> getInstanceTypeInfoMap().values().stream()
        .collect(Collectors.toMap(
            IInstanceTypeInfo::getPropertyName,
            Function.identity(),
            (v1, v2) -> v2,
            LinkedHashMap::new))));
  }

  @Override
  protected Map<String, IPropertyTypeInfo> getPropertyTypeInfoMap() {
    return ObjectUtils.notNull(propertyNameToTypeInfoMap.get());
  }

  @Override
  protected Map<IInstance, IInstanceTypeInfo> getInstanceTypeInfoMap() {
    return ObjectUtils.notNull(instanceToTypeInfoMap.get());
  }

  private Stream<? extends IModelInstanceTypeInfo> processModel(
      @NonNull IContainerModelAbsolute model) {
    Stream<IModelInstanceTypeInfo> modelInstances = Stream.empty();
    // create model instances for the model
    for (IModelInstanceAbsolute instance : model.getModelInstances()) {
      assert instance != null;

      if (instance instanceof IChoiceGroupInstance) {
        modelInstances = Stream.concat(
            modelInstances,
            Stream.of(getTypeResolver().getTypeInfo((IChoiceGroupInstance) instance, this)));
      } else if (instance instanceof IChoiceInstance) {
        modelInstances = Stream.concat(
            modelInstances,
            processModel((IChoiceInstance) instance));
      } else if (instance instanceof INamedModelInstanceAbsolute) {
        // else the instance is an object model instance with a name
        modelInstances = Stream.concat(
            modelInstances,
            Stream.of(getTypeResolver().getTypeInfo((INamedModelInstanceAbsolute) instance, this)));
      }
    }
    return modelInstances;
  }
}
