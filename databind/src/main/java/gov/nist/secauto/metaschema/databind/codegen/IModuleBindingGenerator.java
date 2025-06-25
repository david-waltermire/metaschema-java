/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.codegen;

import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;

import edu.umd.cs.findbugs.annotations.NonNull;

@FunctionalInterface
public interface IModuleBindingGenerator {
  @NonNull
  Class<? extends IBoundModule> generate(@NonNull IModule module) throws MetaschemaException;
}
