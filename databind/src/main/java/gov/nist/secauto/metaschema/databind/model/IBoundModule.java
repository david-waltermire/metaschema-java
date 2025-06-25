/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model;

import gov.nist.secauto.metaschema.core.model.IModuleExtended;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IBoundModule
    extends IModuleExtended<
        IBoundModule,
        IBoundDefinitionModelComplex,
        IBoundDefinitionFlag,
        IBoundDefinitionModelField<?>,
        IBoundDefinitionModelAssembly> {

  @NonNull
  static IBoundModule newInstance(
      @NonNull Class<? extends IBoundModule> clazz,
      @NonNull IBindingContext bindingContext,
      @NonNull List<? extends IBoundModule> importedModules) {

    Constructor<? extends IBoundModule> constructor;
    try {
      constructor = clazz.getDeclaredConstructor(List.class, IBindingContext.class);
    } catch (NoSuchMethodException ex) {
      throw new IllegalArgumentException(ex);
    }

    try {
      return ObjectUtils.notNull(constructor.newInstance(importedModules, bindingContext));
    } catch (InstantiationException | IllegalAccessException | InvocationTargetException ex) {
      throw new IllegalArgumentException(ex);
    }
  }

  /**
   * Get the Module binding context.
   *
   * @return the context
   */
  @NonNull
  IBindingContext getBindingContext();

  @Override
  default URI getLocation() {
    // not known
    return null;
  }

  @Override
  Collection<IBoundDefinitionModelAssembly> getAssemblyDefinitions();

  @Override
  IBoundDefinitionModelAssembly getAssemblyDefinitionByName(@NonNull Integer name);

  @Override
  Collection<IBoundDefinitionModelField<?>> getFieldDefinitions();

  @Override
  IBoundDefinitionModelField<?> getFieldDefinitionByName(@NonNull Integer name);
}
