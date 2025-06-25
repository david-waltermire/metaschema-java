/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.codegen.typeinfo;

import com.squareup.javapoet.AnnotationSpec;
import com.squareup.javapoet.TypeSpec;

import gov.nist.secauto.metaschema.core.model.IModelDefinition;

import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IGroupedNamedModelInstanceTypeInfo {
  @NonNull
  Set<IModelDefinition> generateMemberAnnotation(
      @NonNull AnnotationSpec.Builder choiceGroupAnnotation,
      @NonNull TypeSpec.Builder typeBuilder,
      boolean requireExtension);
}
