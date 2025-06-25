/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.codegen.typeinfo.def;

import com.squareup.javapoet.ClassName;

import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IInstance;
import gov.nist.secauto.metaschema.core.model.IModelDefinition;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.FlagInstanceTypeInfoImpl;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IFlagInstanceTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IInstanceTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.IPropertyTypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.ITypeInfo;
import gov.nist.secauto.metaschema.databind.codegen.typeinfo.ITypeResolver;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

public abstract class AbstractModelDefinitionTypeInfo<DEF extends IModelDefinition>
    implements IModelDefinitionTypeInfo {
  private static final Logger LOGGER = LogManager.getLogger(AbstractModelDefinitionTypeInfo.class);
  @NonNull
  private final DEF definition;
  @NonNull
  private final ITypeResolver typeResolver;
  @NonNull
  private final ClassName className;
  @Nullable
  private final ClassName baseClassName;
  @NonNull
  private final List<ClassName> superinterfaces;
  @NonNull
  private final Lazy<Map<String, IFlagInstanceTypeInfo>> flagTypeInfos;

  public AbstractModelDefinitionTypeInfo(
      @NonNull DEF definition,
      @NonNull ITypeResolver typeResolver) {
    this.definition = definition;
    this.typeResolver = typeResolver;
    this.className = typeResolver.getClassName(definition);
    this.baseClassName = typeResolver.getBaseClassName(definition);
    this.superinterfaces = typeResolver.getSuperinterfaces(definition);
    this.flagTypeInfos = ObjectUtils.notNull(Lazy.of(() -> flags()
        .collect(CustomCollectors.toMap(
            ITypeInfo::getPropertyName,
            CustomCollectors.identity(),
            (key, v1, v2) -> {
              if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("Unexpected duplicate flag property name '%s'", key));
              }
              return ObjectUtils.notNull(v2);
            },
            LinkedHashMap::new))));
  }

  @Override
  public DEF getDefinition() {
    return definition;
  }

  @Override
  public ITypeResolver getTypeResolver() {
    return typeResolver;
  }

  @Override
  public ClassName getClassName() {
    return className;
  }

  @Override
  public ClassName getBaseClassName() {
    return baseClassName;
  }

  @Override
  public List<ClassName> getSuperinterfaces() {
    return superinterfaces;
  }

  private Stream<IFlagInstanceTypeInfo> flags() {
    return getDefinition().getFlagInstances().stream()
        .map(instance -> {
          assert instance != null;
          return new FlagInstanceTypeInfoImpl(instance, this);
        });
  }

  @NonNull
  protected abstract Map<String, IPropertyTypeInfo> getPropertyTypeInfoMap();

  @NonNull
  protected abstract Map<IInstance, IInstanceTypeInfo> getInstanceTypeInfoMap();

  @NonNull
  protected Map<String, IFlagInstanceTypeInfo> getFlagInstanceTypeInfoMap() {
    return ObjectUtils.notNull(flagTypeInfos.get());
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IPropertyTypeInfo> getPropertyTypeInfos() {
    return getPropertyTypeInfoMap().values();
  }

  @Override
  @Nullable
  public IInstanceTypeInfo getInstanceTypeInfo(@NonNull IInstance instance) {
    return getInstanceTypeInfoMap().get(instance);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IInstanceTypeInfo> getInstanceTypeInfos() {
    return getInstanceTypeInfoMap().values();
  }

  @Override
  public IFlagInstanceTypeInfo getFlagInstanceTypeInfo(@NonNull IFlagInstance instance) {
    return (IFlagInstanceTypeInfo) getInstanceTypeInfo(instance);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IFlagInstanceTypeInfo> getFlagInstanceTypeInfos() {
    return getFlagInstanceTypeInfoMap().values();
  }
}
